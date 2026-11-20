# Fixed guest programs comparison specification (before guest implementation)

## Inputs and state

Native x86-64 Linux must run in a network namespace with no network access. The guest environment is cases.json, with an empty/nonexistent PATH so node is unavailable. Native HOME/TMPDIR are dedicated scratch directories, mapped to their guest equivalents. Each probe item starts in a separate fresh fixture. All eight items must emit exactly PASS <name> and exit 0. A no-argument standard run must emit all eight in their listed order and exit 0.

Aube receives freshly built identical bytes. Each side starts from fixtures/ and runs --version, install, removes app/node_modules, install --frozen-lockfile, then list. List uses frozen's state. No registry packages or node installation are permitted. The linked package is outside app, but inside the explicitly provided fixture root. Read-only package manifests are data fixtures, independently authored here, not another project's code.

## Comparison rules

Compare exit and complete stdout and stderr; never remove FAIL lines, missing checks, unknown lines or mismatched package/version content. Remove ANSI SGR decoration, replace only the exact temporary fixture root with <FIXTURE>, and replace explicitly recognized elapsed-time fields in aube output with <ELAPSED>. Do not erase arbitrary numbers, addresses, versions or entire lines. Preserve original stdout/stderr before normalization. Filesystem snapshots are retained for diagnosis; any new normalization rule must be documented and cannot silently convert a mismatch into success.

Fixture package manifests are regular files with mode 0644, observed by the native Linux metadata oracle. C10's optional initial file_modes preserve those permissions; existing with_file and program placement retain 0755. Both input modes and original outputs are recorded. The bounded mounted fixture prepares tmp and home/u10 directories before guest operations; the default VFS install remains a required comparison.

Node absence is observed independently using the probe's environment diagnostic, with ENOENT required. Native network namespace identity and empty routing are recorded; namespace failure is infrastructure failure, not a guest PASS. Every operation has a 30-second outer deadline and child process-group cleanup/reaping, even after nominal success. Expected outputs are generated in each CI run and are never checked in as golden files.

## ripgrep and coreutils

ripgrep and uutils coreutils are built from the fixed releases in source-lock.json, audited before any guest is compiled, and compared on x86-64 Linux with fresh native rows from the same bytes. Their rows are compared exactly: exit, stdout, stderr and that the guest exited by itself. No normalization is applied, because both print only the relative paths they are given.

ripgrep runs the searches in ripgrep-cases.json in fixture/app, before aube changes it.

coreutils is one multicall binary, run as `coreutils <utility> ...`; the emulator gives it the guest path /coreutils, which is also its argv[0], because the binary chooses the utility by that name. Each case in coreutils-cases.json starts from a fresh copy of coreutils-fixture, whose files are 0644. A case marked writes runs on the copy mounted at the guest's /, and the copy's file contents afterwards are compared too. The other cases run on the emulator's own file system. A case with stdin gives a fixture file's bytes on a pipe natively and as the emulator's stdin. TZ=UTC comes from cases.json; the one case with its own TZ uses the POSIX string JST-9, which needs no time zone files. Usage errors are left out, because they name the binary by argv[0]. id, uname, pwd and env are left out, because they print the host's identity, path and environment, which differ by design. Every coreutils case runs before a mismatch is raised, so one run lists every difference.

coreutils' audit uses the root deny.toml with one license exception, for coreutils alone: notify 8.2.2 (CC0-1.0, through uu_tail), whose full license text the build keeps. It is built with `--no-default-features --features feat_os_unix_musl`, because stdbuf's cdylib cannot be built for musl.
