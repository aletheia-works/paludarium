# Security policy

## Supported versions

Security fixes target the current `main` branch and the latest published
release of the paludarium crates and `@aletheia-works/paludarium-wasm`. Older versions do not
have a separate long-term support commitment.

## Reporting a vulnerability

Do not disclose vulnerabilities in public issues. If the repository's Security
tab offers **Report a vulnerability**, use GitHub Private Vulnerability Reporting.
Otherwise email **jambalaya.pyoncafe@gmail.com**, the organization's security contact.

paludarium runs untrusted x86-64 Linux programs. Reports of a guest escaping
its virtual file system or reaching host resources it was not given, a guest
input that makes the emulator panic or misbehave, and supply-chain issues in
the release workflow are all in scope.

Include the affected commit or package version, the host (OS, CPU, native or
wasm, and the Node.js or browser version), build information, minimal
reproduction steps with the guest program or how to build it, observed output,
and impact. Remove secrets and sensitive data from all examples.

Reports are handled on a best-effort basis without a fixed response timeline.
Disclosure timing will be coordinated before publication. There is no bug-bounty
program. AI-assisted reports must include a verified reproduction.

See the [organization security policy](https://github.com/aletheia-works/.github/blob/main/SECURITY.md)
for shared expectations.
