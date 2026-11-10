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

# Even if every case ran out its time, the cases would end in 165
# minutes (120 cases on 4 workers, 330 s each), within the workflow's 180 with
# room for the checkout, the build and the image. results.json is written
# after each case, so a job stopped at its limit still keeps the ones that
# ended. The slowest cases, Emacs and g++, took up to 180 s under the emulator
# on CI, and under a second natively; all of them took 12 minutes.
SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
NATIVE_TIMEOUT = 30
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
        "Makefile.j": "all: "
        + " ".join(f"t{i}" for i in range(8))
        + "\n\t@cat $(O)/t* | sort -n | tr '\\n' ' '; echo\n"
        + "".join(f"t{i}:\n\t@echo {i} > $(O)/t{i}\n" for i in range(8)),
    }
    for name, text in files.items():
        with open(os.path.join(fx, name), "w") as file:
            file.write(text)
    return fx


def cases(fx):
    """Each case's argv; {O} is replaced by the case's own empty directory."""

    def shell(script):
        return ["/bin/bash", "-c", script]

    return runtimes(shell) | {
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
        # Signals, processes, sockets, pseudo-terminals, locks and /proc.
        "python-signals": ["/usr/bin/python3", f"{SCRIPTS}/signals.py"],
        "python-sockets": ["/usr/bin/python3", f"{SCRIPTS}/sockets.py"],
        "python-processes": ["/usr/bin/python3", f"{SCRIPTS}/processes.py"],
        "python-proc": ["/usr/bin/python3", f"{SCRIPTS}/proc.py"],
        "python-pty": ["/usr/bin/python3", f"{SCRIPTS}/terminals.py"],
        # Through netlink: ip, glibc's getifaddrs and if_nameindex, on the loopback.
        "interfaces": ["/usr/bin/python3", f"{SCRIPTS}/interfaces.py"],
        # script runs a shell on a pseudo-terminal and waits on a signalfd for its SIGCHLD. The
        # terminal echoes the piped line; the log's header and footer lines carry the date.
        "script": shell(
            "printf 'abc\\n' | script -qec 'read x; echo got $x; tty | sed s/[0-9]*$//; stty size; "
            "exit 3' {O}/t; echo rc=$?; tr -d '\\r' < {O}/t | grep -v '^Script '"
        ),
        # ps and pgrep read the /proc directories of this shell's children, sleep's once it
        # sleeps. Only the children: the native side shares its /proc with the other cases.
        # STIME needs the boot time from /proc/stat; only whether ps finds it is compared.
        "ps": shell(
            'sleep 30 & s=$!; until [ "$(cat /proc/$s/comm 2>/dev/null)" = sleep ] && '
            "grep -q 'State:.S' /proc/$s/status; do :; done; "
            "ps -o user=,stat=,tty=,time=,nlwp=,ni=,comm= --ppid $$ > {O}/p; sort {O}/p; "
            "ps -o args= -p $s; ps -L -o nlwp=,comm= -p $s; readlink /proc/$s/exe /proc/$s/cwd; "
            "ps -o stime= -p $s > /dev/null; echo stime $?; "
            '[ "$(pgrep -x -P $$ sleep)" = "$s" ] && echo pgrep found; kill $s; wait $s; echo $?'
        ),
        "timeout": shell("timeout 0.2 sleep 5; echo $?; timeout -s KILL 0.2 sleep 5; echo $?"),
        "bash-trap": shell(
            "trap 'echo got USR1' USR1; kill -USR1 $$; echo after; "
            "trap 'echo exit trap' EXIT; (exit 4); echo sub $?"
        ),
        "bash-jobs": shell(
            "for i in $(seq 20); do (echo $i) & done | sort -n | tr '\\n' ' '; echo; "
            "sleep 5 & kill %1; wait %1; echo status $?"
        ),
        "xargs": shell("seq 100 | xargs -P4 -n10 echo | wc -l"),
        "text": shell(
            "printf 'b\\na\\nc\\na\\n' | sort | uniq -c; echo abc | tr a-c x-z; seq 10 | paste -sd+ | bc; "
            "printf 'x\\ty\\n' | expand -t4; seq 5 | tac | nl; echo hello | base64 | base64 -d; "
            f"cut -d' ' -f2 {fx}/words | head -3; join <(seq 3) <(seq 2 4); comm -12 <(seq 4) <(seq 3 6)"
        ),
        "files": shell(
            "cd {O} && mkdir -p a/b && echo x > a/b/f && cp -a a c && ln -s c/b/f l && readlink l && "
            "mv c d && du -sb a/b/f | cut -f1 && chmod 640 a/b/f && stat -c %a a/b/f && "
            "touch -d @0 a/b/f && stat -c %Y a/b/f && ls -R a d && install -m 700 a/b/f e && stat -c %a e && "
            "realpath -s --relative-to=. d/b/f && rm -r a && ls"
        ),
        "split": shell(
            "cd {O} && seq 1000 > n && split -l 300 n p && wc -l p* && cat p* | cmp - n && echo same"
        ),
        # Four processes write to one database in WAL mode at once; SQLite takes
        # fcntl's byte-range locks on the database and on its -shm file.
        "sqlite-wal": shell(
            "cd {O} && sqlite3 w.db 'pragma journal_mode=wal; create table t(a);' && "
            "for i in 1 2 3 4; do (for j in $(seq 50); do "
            "sqlite3 -cmd '.timeout 5000' w.db \"insert into t values($i)\"; done) & done; wait; "
            "sqlite3 w.db 'select count(*), count(distinct a) from t; pragma integrity_check;'"
        ),
        # A FIFO between a background writer and a reader, then one descriptor
        # opened for both ends, and Python's os.mkfifo with a writer thread.
        "mkfifo": shell(
            "cd {O} && mkfifo -m 600 p && stat -c '%F %a' p && { echo through the fifo > p & } && cat p && wait && "
            "exec 3<>p && echo both ends >&3 && read -r line <&3 && echo $line && exec 3<&- && "
            'python3 -c \'import os, threading; os.mkfifo("q"); '
            't = threading.Thread(target=lambda: open("q", "w").write("python\\n")); t.start(); '
            'print(open("q").read().strip()); t.join()\''
        ),
        "flock": shell(
            "flock {O}/l -c 'echo locked'; flock {O}/l -c 'flock -n {O}/l true; echo inner $?'"
        ),
        "perl-fork": [
            "/usr/bin/perl",
            "-e",
            'pipe(R,W); if (my $p = fork) { close W; print <R>; waitpid($p, 0); print $? >> 8, "\\n" } '
            'else { close R; print W "child\\n"; exit 3 }',
        ],
        "ruby-io": [
            "/usr/bin/ruby",
            "-e",
            'r, w = IO.pipe; pid = fork { r.close; w.puts "kid"; exit 4 }; w.close; puts r.read; '
            "Process.wait(pid); puts $?.exitstatus; q = Queue.new; "
            "4.times.map { |i| Thread.new { q << i * i } }.each(&:join); puts 4.times.map { q.pop }.sort.inspect",
        ],
        "node-worker": [
            "/usr/bin/node",
            "-e",
            'const { Worker } = require("worker_threads"); '
            "new Worker(\"require('worker_threads').parentPort.postMessage(6 * 7)\", { eval: true })"
            '.on("message", (m) => console.log("worker", m));',
        ],
        # Child processes whose standard streams are pipes, one after another.
        "node-child-process": [
            "/usr/bin/node",
            "-e",
            'const cp = require("child_process"); '
            'const r = cp.spawnSync("/bin/sh", ["-c", "echo sync; exit 3"]); '
            "console.log(r.status, String(r.stdout).trim()); "
            'cp.execFile("/bin/echo", ["async"], (error, out) => { console.log(error, out.trim()); '
            'const cat = cp.spawn("/bin/cat"); cat.stdout.on("data", (d) => process.stdout.write("cat " + d)); '
            'cat.on("close", (code) => console.log("closed", code)); cat.stdin.end("piped\\n"); });',
        ],
        "php-proc": [
            "/usr/bin/php",
            "-n",
            "-r",
            '$p = proc_open(["/bin/cat"], [["pipe", "r"], ["pipe", "w"]], $io); fwrite($io[0], "via cat\\n"); '
            'fclose($io[0]); echo stream_get_contents($io[1]); echo proc_close($p), "\\n";',
        ],
        "lua-popen": [
            "/usr/bin/lua5.4",
            "-e",
            'local f = io.popen("echo popen"); io.write(f:read("a")); print(f:close())',
        ],
        "gawk-coprocess": [
            "/usr/bin/gawk",
            'BEGIN { while (("seq 3" | getline x) > 0) s += x; print s; '
            'print "z\\ny" |& "sort"; close("sort", "to"); while (("sort" |& getline l) > 0) print l }',
        ],
        "git-clone": shell(
            "cd {O} && git init -q -b main a && cd a && git config user.email a@b && git config user.name a && "
            "for i in 1 2 3; do echo $i > f$i; git add f$i; "
            "GIT_AUTHOR_DATE=2001-01-01T00:00:00Z GIT_COMMITTER_DATE=2001-01-01T00:00:00Z git commit -qm c$i; done && "
            "git gc -q && cd .. && git clone -q a b && cd b && git rev-parse HEAD && git log --oneline | wc -l && "
            "git fsck --no-progress && echo fsck ok"
        ),
        "zip": shell(
            "cd {O} && zip -qr z.zip /usr/share/doc/bash -x '*.gz' && unzip -l z.zip | tail -1 | awk '{print $2}' && "
            "mkdir x && unzip -q z.zip -d x && find x -type f | wc -l"
        ),
        "diff-patch": shell(
            "cd {O} && seq 10 > a && seq 10 | sed 5d > b && diff -u a b > d; echo $?; "
            "cp a c && patch -s c d && cmp b c && echo patched"
        ),
        "make-j": ["/usr/bin/make", "-j4", "-s", "-f", f"{fx}/Makefile.j", "O={O}"],
        "nproc": shell(
            'test "$(nproc)" = "$(getconf _NPROCESSORS_ONLN)" && echo agree; getconf PAGESIZE'
        ),
        "env": shell("env -i /usr/bin/env; env -i A=1 /usr/bin/env"),
        "iconv": shell("printf 'caf\\303\\251\\n' | iconv -f UTF-8 -t ISO-8859-1 | od -An -tx1"),
        "dd": shell(
            "dd if=/dev/zero bs=1k count=100 status=none | wc -c; "
            "dd if=/dev/urandom bs=1 count=16 status=none | wc -c"
        ),
        "tz": shell(
            "TZ=Asia/Tokyo date -d @0 '+%F %T %Z'; TZ=America/New_York date -d @1700000000 '+%F %T %Z'"
        ),
        "sort-parallel": shell(f"sort --parallel=4 -S 1M -n -T {{O}} {fx}/words | sha256sum"),
        "find-exec": shell("find /usr/share/doc/bash -type f -exec wc -c {} + | tail -1"),
        "tar-gz": shell(
            "cd {O} && mkdir t && echo a > t/f && chmod 751 t/f && ln -s f t/l && tar czf t.tgz t && "
            "mkdir x && tar xzf t.tgz -C x && stat -c '%a %F' x/t/f x/t/l"
        ),
        # Built by the Dockerfile; the go command itself only reports its version.
        "go": shell("/usr/local/bin/goroutines && go version | cut -d' ' -f1-2"),
        "python-stdlib": ["/usr/bin/python3", f"{SCRIPTS}/stdlib.py"],
        "redis": shell(
            "cd {O} && (redis-server --port 16379 --bind 127.0.0.1 --save '' --appendonly no "
            "--dir {O} >/dev/null &) && for i in $(seq 200); do redis-cli -p 16379 ping 2>/dev/null && break; "
            "sleep 0.1; done && redis-cli -p 16379 set k v && redis-cli -p 16379 incrby n 41 && "
            "redis-cli -p 16379 incr n && redis-cli -p 16379 lpush l a b c && redis-cli -p 16379 lrange l 0 -1 && "
            "redis-cli -p 16379 shutdown nosave; true"
        ),
        "http-server": shell(
            "cd {O} && echo served > page && { python3 -m http.server 18080 --bind 127.0.0.1 "
            ">/dev/null 2>&1 & } && server=$! && for i in $(seq 200); do curl -sf http://127.0.0.1:18080/page && "
            "break; sleep 0.1; done && curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:18080/missing; "
            "kill $server; wait $server; echo server $?"
        ),
        "busybox": shell(
            "busybox echo hi; echo 'b a' | busybox awk '{print $2, $1}'; busybox seq 3 | busybox sed 's/^/n/'; "
            "printf 'x\\ny\\n' | busybox sort -r; busybox sh -c 'for i in 1 2; do echo sh$i; done'; "
            "busybox expr 6 \\* 7"
        ),
        "zsh": [
            "/usr/bin/zsh",
            "-c",
            "setopt extendedglob; a=(3 1 2); print -l ${(n)a}; print ${${:-hello}:u}; "
            "f() { print args $#; }; f 1 2 3; (( x = 2 ** 10 )); print $x; sleep 0.1 & wait; print waited $?",
        ],
        "mksh": [
            "/bin/mksh",
            "-c",
            "typeset -i n=0; while (( n < 3 )); do (( n++ )); done; echo $n; "
            "set -A a z y; echo ${a[1]}; echo $(( 7 % 3 )); trap 'echo trapped' EXIT",
        ],
        "emacs": [
            "/usr/bin/emacs",
            "--batch",
            "--eval",
            '(progn (princ (format "%s\\n" (mapcar (lambda (x) (* x x)) (number-sequence 1 5)))) '
            '(princ (format "%s\\n" (string-to-number "42"))) '
            '(with-temp-buffer (insert "b\\na\\n") (sort-lines nil (point-min) (point-max)) '
            "(princ (buffer-string))))",
        ],
        "perl-threads": [
            "/usr/bin/perl",
            "-Mthreads",
            "-MJSON::PP",
            "-MDigest::SHA=sha256_hex",
            "-e",
            "my @t = map { threads->create(sub { $_[0] * 2 }, $_) } 1..4; print join(',', map { $_->join } @t), \"\\n\"; "
            "print JSON::PP->new->canonical->encode({b => [1, 2], a => 'x'}), \"\\n\"; print sha256_hex('abc'), \"\\n\";",
        ],
        "coreutils-more": shell(
            "cd {O} && seq 10 | shuf --random-source=<(yes) | sort -n | tr '\\n' ' '; echo; "
            "printf abc | tee t1 | head -c 2; echo; truncate -s 5000 sp && stat -c %s sp && "
            "cp --sparse=always sp sp2 && cmp sp sp2 && echo sparse-same; mktemp -p . tmp.XXXX | wc -c; "
            "id -u; nice -n 5 nice; nohup echo detached 2>/dev/null; stdbuf -oL echo buffered; "
            "df -P . | tail -1 | wc -w"
        ),
        "util-linux": shell(
            "getopt -o ab: -- -a -b x y; printf 'a b\\nccc d\\n' | column -t; echo stressed | rev; "
            "printf 'AB' | hexdump -C | head -1; findmnt -n -o TARGET / ; setsid sh -c 'echo new session'; "
            "prlimit --nofile=128 sh -c 'ulimit -n'; taskset -c 0 echo pinned"
        ),
        "compressors": shell(
            "cd {O} && seq 10000 > n && lz4 -q n n.lz4 && lz4 -dc n.lz4 | cmp - n && echo lz4; "
            "brotli -c n > n.br && brotli -dc n.br | cmp - n && echo brotli; "
            "pigz -p 4 -c n > n.gz && gzip -dc n.gz | cmp - n && echo pigz; "
            "lzip -c n > n.lz && lzip -dc n.lz | cmp - n && echo lzip"
        ),
        "ninja": shell(
            "cd {O} && printf 'cmake_minimum_required(VERSION 3.10)\\nproject(p C)\\n"
            "add_executable(p p.c)\\n' > CMakeLists.txt && printf 'int main(void){return 7;}\\n' > p.c && "
            "cmake -G Ninja -S . -B b >/dev/null && ninja -C b >/dev/null && ./b/p; echo status $?"
        ),
        "parallel": shell(
            "seq 8 | parallel --will-cite -j4 -k 'echo job {}; echo {} >&2' 2>/dev/null; "
            "parallel --will-cite -k echo ::: a b ::: 1 2"
        ),
        "ed": shell(
            "cd {O} && printf 'one\\ntwo\\n' > f && printf '2s/two/2/\\n1i\\nzero\\n.\\nw\\nq\\n' | ed -s f && cat f"
        ),
    }


def runtimes(shell):
    """Language runtimes with their own threads, memory management or JIT, and
    servers on the loopback."""
    return {
        # java finds libjli.so from its own path ($ORIGIN), and erl is a script.
        # The class is compiled by the Dockerfile.
        "java": ["/usr/bin/java", "-cp", "/opt/java", "Threads"],
        "erlang": [
            "/usr/bin/erl",
            "-noshell",
            "-eval",
            "Self = self(), [spawn(fun() -> Self ! {sq, N * N} end) || N <- lists:seq(1, 5)], "
            "L = [receive {sq, V} -> V end || _ <- lists:seq(1, 5)], "
            'io:format("~p ~p~n", [lists:sort(L), lists:sum([X * X || X <- lists:seq(1, 100)])]), halt().',
        ],
        "sbcl": [
            "/usr/bin/sbcl",
            "--non-interactive",
            "--no-userinit",
            "--no-sysinit",
            "--eval",
            "(progn (print (loop for i from 1 to 100 sum (* i i))) "
            "(let ((v (make-array 1000000 :initial-element 1))) (sb-ext:gc :full t) (print (reduce #'+ v))) "
            "(print (length (make-list 100000))) (terpri))",
        ],
        "luajit": [
            "/usr/bin/luajit",
            "-e",
            "local s = 0 for i = 1, 1e7 do s = s + i % 7 end print(s) print((jit.status()))",
        ],
        "ocaml": shell(
            'cd {O} && echo \'let () = List.iter (Printf.printf "%d ") (List.sort compare [3; 1; 2]); '
            'print_newline (); Printf.printf "%.3f\\n" (sqrt 2.)\' > t.ml && ocaml t.ml'
        ),
        "r": [
            "/usr/bin/Rscript",
            "-e",
            "x <- c(3, 1, 2); print(sort(x)); d <- data.frame(x = 1:10, y = 2 * (1:10) + 1); "
            "print(round(coef(lm(y ~ x, d)), 6)); print(sum(sapply(1:100, function(i) i^2)))",
        ],
        "guile": [
            "/usr/bin/guile",
            "-c",
            "(display (apply + (map (lambda (x) (* x x)) (iota 10)))) (newline)",
        ],
        # A shell written in Rust; its command substitution duplicates a pipe
        # with fcntl from a register whose upper half is not cleared.
        "fish": [
            "/usr/bin/fish",
            "--no-config",
            "-c",
            "for i in (seq 3); echo n$i; end; math 6 \\* 7; set -l l a b c; echo (count $l); "
            "function f; echo args $argv; end; f x y",
        ],
        "pandoc": shell(
            "printf '# Title\\n\\nSome *emphasis* and `code`.\\n' | pandoc -f markdown -t html"
        ),
        "graphviz": shell(
            "echo 'digraph { a -> b; b -> c; }' | dot -Tsvg | grep -c '<g id=\"node'"
        ),
        "imagemagick": shell(
            "cd {O} && convert -size 16x8 xc:red -fill blue -draw 'rectangle 0,0 7,7' i.png && "
            "identify -format '%wx%h %m\\n' i.png && convert i.png -format '%[pixel:p{1,1}] %[pixel:p{12,4}]\\n' info:"
        ),
        # Its workers run as www-data, whose temporary directories the master
        # chowns to it.
        "nginx": shell(
            "cd {O} && mkdir www logs && echo from nginx > www/index.html && "
            "printf 'daemon off; user www-data www-data; worker_processes 2; error_log {O}/logs/error.log; pid {O}/nginx.pid;\\n"
            "events {}\\nhttp { access_log off; server { listen 127.0.0.1:18081; root {O}/www; } }\\n' > nginx.conf && "
            "{ /usr/sbin/nginx -p {O}/ -c {O}/nginx.conf & } && server=$! && for i in $(seq 200); do "
            "curl -sf http://127.0.0.1:18081/ && break; sleep 0.1; done && "
            "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:18081/missing; kill -QUIT $server; wait $server; "
            "echo server $?"
        ),
        # The server runs as postgres, in a data directory root gave it, and
        # answers on a socket in the case's directory only; its log is kept
        # there too, as postgres cannot write to the case's own directory.
        "postgresql": shell(
            "cd {O} && mkdir pg s && chown postgres:postgres pg s && b=$(echo /usr/lib/postgresql/*/bin) && "
            "setpriv --reuid=postgres --regid=postgres --init-groups /bin/sh -c '"
            "$0/initdb -D {O}/pg -A trust -E UTF8 --locale=C.UTF-8 >/dev/null && "
            '$0/pg_ctl -D {O}/pg -o "-k {O}/s -c listen_addresses=" -w -l {O}/s/log start >/dev/null && '
            '$0/psql -h {O}/s -d postgres -XAtc "create table t(a int, b text); '
            "insert into t select i, md5(i::text) from generate_series(1, 1000) i; "
            'select count(*), sum(a), max(b) from t; select current_user"; '
            "$0/pg_ctl -D {O}/pg -m fast -w stop >/dev/null; echo stopped $?' $b; "
            "stat -c '%U %G %a' pg"
        ),
        "memcached": shell(
            "{ memcached -u root -l 127.0.0.1 -p 11311 -t 2 & } && server=$! && for i in $(seq 200); do "
            "printf 'version\\r\\n' | socat -t1 - TCP:127.0.0.1:11311 >/dev/null 2>&1 && break; sleep 0.1; done && "
            "printf 'set k 0 0 5\\r\\nhello\\r\\nget k\\r\\nincr n 1\\r\\nquit\\r\\n' | socat -t2 - TCP:127.0.0.1:11311 "
            "| tr -d '\\r'; kill $server; wait $server; echo server $?"
        ),
        "socat": shell(
            "{ socat TCP-LISTEN:18082,bind=127.0.0.1,reuseaddr,fork EXEC:'tr a-z A-Z' & } && server=$! && "
            "for i in $(seq 200); do echo probe | socat -t1 - TCP:127.0.0.1:18082 >/dev/null 2>&1 && break; sleep 0.1; done; "
            "echo through socat | socat -t2 - TCP:127.0.0.1:18082; kill $server; wait $server 2>/dev/null; echo done"
        ),
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


# The emulator's own options for a case. Without --allow-net a guest has no
# network, not even a loopback (docs/guide/features.md#network).
OPTIONS = {
    name: ["--allow-net", "127.0.0.1"]
    for name in (
        "python-sockets",
        "redis",
        "http-server",
        "nginx",
        "memcached",
        "socat",
        "interfaces",
    )
}


def command(argv, directory, emulator, env, options=()):
    """The argv with {O} replaced, run directly or through the emulator."""
    argv = [part.replace("{O}", directory) for part in argv]
    if emulator is None:
        return argv
    options = [emulator, "--report-enosys", "--mount", "/:/", *options]
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
            command(argv, directory, emulator, env, OPTIONS.get(name, ())),
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
