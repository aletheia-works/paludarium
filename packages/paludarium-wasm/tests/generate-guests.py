"""Deterministic freestanding x86-64 Linux ELF fixtures; no assembler dependency."""

import argparse
import pathlib
import struct

CODES = {
    "hello": "b801000000bf0100000048be0020400000000000ba060000000f05b83c00000031ff0f05",
    "integer": "b80700000083c02389c7b83c0000000f05",
    "atomic": "48b90020400000000000b801000000f0480fc1014883c02a4889c7b83c0000000f05",
    "divide_fault": "31d231c931c0f7f1",
    "stdin": "31c031ff48be0020400000000000ba060000000f054889c2b801000000bf010000000f05b83c00000031ff0f05",
    "infinite": "ebfe",
}

# U3 instruction forms execute through the production Session/launcher. These
# bytes are inputs only; native output and signal expectations are regenerated.
U3_OPS = {
    "encodings-packed": "660f3804c1",  # PMADDUBSW: signed saturation and lane pairing
    "encodings-sha": "0f38cbc10f38ccc10f38cdc1",
    "encodings-aes": "660f38dcc1660f38ddc1",
    "encodings-pclmul": "660f3a44c100660f3a44c111",
    "encodings-float": "660f58c1f20f59c1f20f51c0",  # ADDPD, MULSD, SQRTSD
    "encodings-fault": "f20f51c0",  # SQRTSD negative finite operand: SIGFPE
}
for name, operation in U3_OPS.items():
    load = "48b80020400000000000f30f6f00f30f6f4810"
    # Unmask invalid only for the explicit fault fixture.
    control = "0fae9040000000" if name == "encodings-fault" else ""
    store = "f30f7f8020000000"
    write_exit = "b801000000bf0100000048be2020400000000000ba100000000f05b83c00000031ff0f05"
    CODES[name] = load + control + operation + store + write_exit
CODES["encodings-cpuid"] = (
    "b80100000031c90fa248bf20204000000000008907895f04894f0889570cb801000000bf0100000048be2020400000000000ba100000000f05b83c00000031ff0f05"
)


def guest(name):
    code = bytes.fromhex(CODES[name])
    data = bytes(64) if name in ("stdin", "infinite") else b"hello\n"
    if name.startswith("encodings-"):
        data = bytearray(80)
        if name in ("encodings-float", "encodings-fault"):
            struct.pack_into(
                "<dddd", data, 0, -1.0 if name == "encodings-fault" else 1.5, 2.0, 2.25, 3.5
            )
        else:
            data[:32] = bytes((n * 17 + 3) & 255 for n in range(32))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    code_segment = struct.pack(
        "<IIQQQQQQ", 1, 5, 4096, 0x401000, 0x401000, len(code), len(code), 4096
    )
    data_segment = struct.pack(
        "<IIQQQQQQ", 1, 6, 8192, 0x402000, 0x402000, len(data), len(data), 4096
    )
    image = bytearray(8192 + len(data))
    image[:176] = header + code_segment + data_segment
    image[4096 : 4096 + len(code)] = code
    image[8192:] = data
    return bytes(image)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = pathlib.Path(__file__).parent / "guests"
    directory.mkdir(exist_ok=True)
    for name in CODES:
        path = directory / name
        image = guest(name)
        if args.check:
            if path.read_bytes() != image:
                raise SystemExit(f"Fixture differs: {name}")
        else:
            path.write_bytes(image)
            path.chmod(0o755)
    print(
        f"All {len(CODES)} deterministic ELF fixtures match"
        if args.check
        else f"Generated {len(CODES)} ELF fixtures"
    )
