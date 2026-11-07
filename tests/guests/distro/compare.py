"""Run a distribution's own dynamically linked programs natively and under
paludarium, and compare their exit status and standard output.

The programs are Debian's glibc builds of shells, interpreters, compilers and
tools, installed by the Dockerfile next to this file. This runs inside that
container; under paludarium the programs run with the container's root mounted
(`--mount /:/`), so they load the same libraries.

    python3 compare.py --emulator /usr/local/bin/paludarium \
        --work /tmp/distro --output /out [CASE...]

Exits 1 when a case differs or times out, and writes results.json to --output.
"""

import argparse
import collections
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import time

# Even if every case ran out its time, the run would end within the workflow's
# 90 minutes: 53 cases on 4 workers, 360 s each. The slowest case takes about
# 75 s under the emulator on CI, and under a second natively.
NATIVE_TIMEOUT = 60
EMULATED_TIMEOUT = 300


def fixtures(work):
    """Write the input files the cases read, under work/fx."""
    fx = os.path.join(work, "fx")
    os.makedirs(fx, exist_ok=True)
    files = {
        "words": "".join(f"{(i * 7919) % 1000} word{i}\n" for i in range(2000)),
        "hello.c": "#include <stdio.h>\n#include <math.h>\n"
        'int main(void){printf("hello %.6f %.6Lf\\n",sqrt(2.0),(long double)1/3);return 0;}\n',
        "e.cc": "#include <iostream>\n#include <stdexcept>\n#include <vector>\n"
        'int main(){std::vector<int> v(3);try{v.at(9);}catch(const std::exception&e){std::cout<<"caught\\n";}'
        'try{throw std::runtime_error("x");}catch(std::exception&e){std::cout<<e.what()<<"\\n";}}\n',
        "t.c": "#include <pthread.h>\n#include <stdio.h>\n"
        "static pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;static long n;"
        "void*f(void*a){for(int i=0;i<100000;i++){pthread_mutex_lock(&m);n++;pthread_mutex_unlock(&m);}return 0;}"
        "int main(){pthread_t t[4];for(int i=0;i<4;i++)pthread_create(t+i,0,f,0);"
        'for(int i=0;i<4;i++)pthread_join(t[i],0);printf("%ld\\n",n);}\n',
        "Makefile": f"all:\n\t@echo built $(shell echo ok)\n\t@cp {fx}/words $(O)/w\n\t@wc -l < $(O)/w\n",
        "x.py": "import math,json,hashlib,decimal,fractions,datetime,zlib,threading,subprocess,sqlite3,ssl,random\n"
        "print(math.sin(1),math.gamma(4.5),math.fsum([.1]*10))\n"
        'print(json.dumps({"a":[1,2.5]},sort_keys=True),hashlib.sha256(b"x").hexdigest())\n'
        "print(decimal.Decimal(1)/7,fractions.Fraction(3,9),datetime.datetime(2020,1,2).isoformat())\n"
        'print(len(zlib.compress(b"a"*10000)))\n'
        'c=sqlite3.connect(":memory:");c.execute("create table t(a)");c.execute("insert into t values(1.5)")\n'
        'print(c.execute("select sum(a) from t").fetchone())\n'
        "r=[];ts=[threading.Thread(target=lambda i=i:r.append(i*i)) for i in range(8)]\n"
        "[t.start() for t in ts];[t.join() for t in ts];print(sorted(r))\n"
        'print(subprocess.run(["/bin/echo","child"],capture_output=True).stdout)\n'
        "random.seed(1);print(random.random());print(ssl.OPENSSL_VERSION)\n",
        "n.json": "[1,2,3.5]",
        "b.bc": "scale=20\ns(1)\ne(1)\nsqrt(2)\nquit\n",
        "x.tcl": 'puts [expr {sin(1)}]\nputs [format "%.4f" [expr {2.0/3}]]\nputs [exec echo sub]\n',
    }
    for name, text in files.items():
        with open(os.path.join(fx, name), "w") as file:
            file.write(text)
    return fx


def cases(fx):
    """Each case's argv; {O} is replaced by the case's own empty directory."""

    def shell(script):
        return ["/bin/bash", "-c", script]

    return {
        "ls": ["/bin/ls", "-la", "/usr/share/doc/bash"],
        "cat": ["/bin/cat", "/etc/os-release"],
        "sort": ["/usr/bin/sort", "-n", f"{fx}/words"],
        "wc": ["/usr/bin/wc", f"{fx}/words"],
        "sha256sum": ["/usr/bin/sha256sum", f"{fx}/words"],
        "date": ["/bin/date", "-u", "-d", "@86400", "+%F %T %A"],
        "seq": ["/usr/bin/seq", "0.5", "0.25", "3"],
        "printf": ["/usr/bin/printf", "%.3f %Lf\\n", "3.14159", "2.5"],
        "stat": ["/usr/bin/stat", "-c", "%s %F %a", "/etc/os-release"],
        "od": ["/usr/bin/od", "-t", "fL", "-N", "32", f"{fx}/words"],
        "numfmt": ["/usr/bin/numfmt", "--to=iec", "1234567"],
        "factor": ["/usr/bin/factor", "600851475143"],
        "grep": ["/bin/grep", "-c", "word1", f"{fx}/words"],
        "sed": ["/bin/sed", "-n", "s/word\\(1.\\)$/\\1/p", f"{fx}/words"],
        "find": ["/usr/bin/find", "/usr/share/doc/bash", "-type", "f", "-name", "*.gz"],
        "gawk": [
            "/usr/bin/gawk",
            'BEGIN{printf "%.9f %.9f %.9f %d\\n",sin(1),exp(1.5),atan2(1,2),2^40}',
        ],
        "mawk": ["/usr/bin/mawk", 'BEGIN{printf "%.9f %.9f\\n",cos(1),log(7)}'],
        "bash": shell(
            'a=0; for i in {1..200}; do a=$((a+i)); done; echo $a; printf "%f %.2e\\n" 1.5 12345; '
            "x=$(echo sub | tr a-z A-Z); echo $x; cat /etc/hostname >/dev/null; (exit 3); echo $?"
        ),
        "dash": [
            "/bin/dash",
            "-c",
            "i=0; while [ $i -lt 50 ]; do i=$((i+1)); done; echo $i; ls /etc/os-release | wc -l",
        ],
        "perl": [
            "/usr/bin/perl",
            "-MPOSIX",
            "-MList::Util=sum",
            "-e",
            'printf "%.9f %.9f %s\\n",sin(1),POSIX::floor(2.7),sum(1..100); print join(",",sort map{$_*2}1..5),"\\n"; '
            'print `echo backtick`; printf "%s\\n", 1e300*1e10;',
        ],
        "python3": ["/usr/bin/python3", f"{fx}/x.py"],
        "sqlite3": [
            "/usr/bin/sqlite3",
            ":memory:",
            "create table t(a,b);insert into t values(1,2.5),(2,3.5);select sum(a),avg(b),sqrt(16.0),pow(2,0.5) from t;",
        ],
        "jq": ["/usr/bin/jq", "-c", "map(.*1.5)|add", f"{fx}/n.json"],
        "bc": ["/usr/bin/bc", "-l", f"{fx}/b.bc"],
        "dc": ["/usr/bin/dc", "-e", "20k 2 v p"],
        "lua": [
            "/usr/bin/lua5.4",
            "-e",
            'print(math.sin(1),string.format("%.3f",2/3),#("x"):rep(100))',
        ],
        "ruby": [
            "/usr/bin/ruby",
            "-e",
            "puts Math.sin(1); puts [3,1,2].sort.inspect; puts 2**100; puts `echo sub`; "
            't=Thread.new{1+1}; puts t.value; begin; raise "x"; rescue=>e; puts e.message; end',
        ],
        "php": [
            "/usr/bin/php",
            "-n",
            "-r",
            'echo sin(1),"\\n",json_encode([1,2.5]),"\\n",md5("x"),"\\n";',
        ],
        "tclsh": ["/usr/bin/tclsh", f"{fx}/x.tcl"],
        "node": [
            "/usr/bin/node",
            "-e",
            'console.log(Math.sin(1),JSON.stringify({a:1}),require("crypto").createHash("sha256").update("x").digest("hex"))',
        ],
        "tar": shell("cd /usr/share/doc && tar cf - bash | tar tf - | sort | head -5"),
        "gzip": shell(f"gzip -c {fx}/words | gunzip | sha256sum"),
        "bzip2": shell(f"bzip2 -c {fx}/words | bunzip2 | sha256sum"),
        "xz": shell(f"xz -T2 -c {fx}/words | xz -d | sha256sum"),
        "zstd": shell(f"zstd -q -c {fx}/words | zstd -qd | sha256sum"),
        "file": ["/usr/bin/file", "/etc/os-release", "/bin/ls"],
        # What rsync changed, one line a file, rather than --stats, whose speed lines vary. The
        # destination is relative, since rsync names it and each side writes to its own directory.
        "rsync": shell("cd {O} && rsync -a -i --no-times /usr/share/doc/bash/ r/ | sort"),
        "git": shell(
            "cd {O} && git init -q -b main r && cd r && git config user.email a@b && git config user.name a && "
            "echo hi > f && git add f && GIT_AUTHOR_DATE=2001-01-01T00:00:00Z GIT_COMMITTER_DATE=2001-01-01T00:00:00Z git commit -qm m && "
            'git log --format="%H %s" && git status --short && git cat-file -p HEAD^{tree}'
        ),
        "openssl": shell(
            f"openssl version; openssl dgst -sha256 {fx}/words; "
            f"openssl enc -aes-256-cbc -pbkdf2 -k k -S 0011223344556677 -in {fx}/words | sha256sum; "
            "openssl rand 8 | wc -c; openssl genpkey -algorithm ed25519 | wc -l"
        ),
        "gpg": ["/usr/bin/gpg", "--homedir", "{O}", "--print-md", "SHA256", f"{fx}/words"],
        "curl": ["/usr/bin/curl", "-s", "file:///etc/os-release"],
        "ssh-keygen": shell(
            "ssh-keygen -q -t ed25519 -N '' -f {O}/k && ssh-keygen -l -f {O}/k | wc -w"
        ),
        "make": ["/usr/bin/make", "-C", fx, "-s", "O={O}"],
        "cmake": ["/usr/bin/cmake", "-E", "sha256sum", f"{fx}/words"],
        "gcc": shell(f"gcc -O2 {fx}/hello.c -o {{O}}/h -lm && {{O}}/h"),
        "gcc-thread": shell(f"gcc -O1 -pthread {fx}/t.c -o {{O}}/t && {{O}}/t"),
        "g++": shell(f"g++ -O1 {fx}/e.cc -o {{O}}/e && {{O}}/e"),
        "as-ld": shell(
            "cd {O} && echo 'nop' | as -o a.o - && ld -r a.o -o b.o && objdump -d b.o | tail -1"
        ),
        "gdb": ["/usr/bin/gdb", "--version"],
        "vim": shell(
            "vim.tiny -u NONE -es -c 'normal ihello' -c 'normal oworld' -c 'w! {O}/v' -c 'q!'; "
            "echo rc=$?; cat {O}/v"
        ),
        "xxd": ["/usr/bin/xxd", "-l", "32", f"{fx}/words"],
        "less": shell("less -F /etc/os-release | wc -l"),
        "dpkg-query": ["/usr/bin/dpkg-query", "-W", "-f=${Version}\\n", "bash"],
    }


def environment(work):
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.path.join(work, "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "TERM": "dumb",
    }


def command(argv, directory, emulator, env):
    """The argv with {O} replaced, run directly or through the emulator."""
    argv = [part.replace("{O}", directory) for part in argv]
    if emulator is None:
        return argv
    options = [emulator, "--report-enosys", "--mount", "/:/"]
    for key, value in env.items():
        options += ["--env", f"{key}={value}"]
    return options + argv


def run(name, argv, work, emulator, env):
    directory = os.path.join(work, "out", "emulated" if emulator else "native", name)
    shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory)
    started = time.monotonic()
    try:
        process = subprocess.run(
            command(argv, directory, emulator, env),
            env=env,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=EMULATED_TIMEOUT if emulator else NATIVE_TIMEOUT,
            cwd="/",
        )
        status, stdout, stderr = process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired as error:
        status, stdout, stderr = "timeout", error.stdout or b"", error.stderr or b""
    return {
        "status": status,
        "stdout": stdout,
        "stderr": stderr,
        "seconds": round(time.monotonic() - started, 1),
    }


def outcome(name, native, emulated):
    """One case's record: whether exit status and stdout match, with the tails of both.

    Every case succeeds natively, so one that fails there is broken and matches nothing:
    a comparison of two failures would check little.
    """

    def text(data, length):
        return data[-length:].decode("latin-1")

    return {
        "name": name,
        "same": native["status"] == 0
        and native["status"] == emulated["status"]
        and native["stdout"] == emulated["stdout"],
        "native": {
            "status": native["status"],
            "seconds": native["seconds"],
            "stdout": text(native["stdout"], 1500),
            "stderr": text(native["stderr"], 800),
        },
        "emulated": {
            "status": emulated["status"],
            "seconds": emulated["seconds"],
            "stdout": text(emulated["stdout"], 1500),
            "stderr": text(emulated["stderr"], 3000),
        },
    }


def enosys(results):
    """Lines of --report-enosys and other unimplemented reports, counted over all cases."""
    counts = collections.Counter()
    for result in results:
        for match in re.finditer(
            r"[^\n]*(?:ENOSYS|enosys|not implemented)[^\n]*", result["emulated"]["stderr"]
        ):
            counts[match.group(0)[:110]] += 1
    return counts


def save(results, output):
    """Replace results.json in output with these results."""
    path = os.path.join(output, "results.json")
    with open(path + ".new", "w") as file:
        json.dump(results, file, indent=1)
    os.replace(path + ".new", path)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--emulator", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("only", nargs="*")
    options = parser.parse_args(arguments)
    work = os.path.abspath(options.work)
    emulator = os.path.abspath(options.emulator)
    env = environment(work)
    os.makedirs(env["HOME"], exist_ok=True)
    table = cases(fixtures(work))
    unknown = set(options.only) - set(table)
    if unknown:
        parser.error(f"unknown cases: {', '.join(sorted(unknown))}")
    selected = [
        (name, argv) for name, argv in table.items() if not options.only or name in options.only
    ]

    def one(item):
        name, argv = item
        return outcome(name, run(name, argv, work, None, env), run(name, argv, work, emulator, env))

    order = [name for name, _ in selected]
    results = []
    os.makedirs(options.output, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(options.jobs) as executor:
        for future in concurrent.futures.as_completed(
            [executor.submit(one, item) for item in selected]
        ):
            result = future.result()
            results.append(result)
            results.sort(key=lambda result: order.index(result["name"]))
            native, emulated = result["native"], result["emulated"]
            print(
                "same" if result["same"] else "DIFF",
                result["name"],
                f"native {native['status']} in {native['seconds']} s,",
                f"emulated {emulated['status']} in {emulated['seconds']} s",
                flush=True,
            )
            # Written after every case, so that a run the job's time limit stops keeps what ended.
            save(results, options.output)
    for line, count in enosys(results).most_common():
        print(f"{count} {line}")
    different = [result["name"] for result in results if not result["same"]]
    print(f"{len(results) - len(different)} of {len(results)} match", flush=True)
    for result in results:
        if not result["same"]:
            print(
                f"--- {result['name']}\nnative:   {result['native']}\nemulated: {result['emulated']}"
            )
    return 1 if different else 0


if __name__ == "__main__":
    sys.exit(main())
