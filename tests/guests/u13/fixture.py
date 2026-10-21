"""Guest-visible fixture modes, checked again against the Rust Host boundary."""

import os
import stat

FILES = [
    ("app/package.json", "/package.json"),
    ("app/filedep/package.json", "/filedep/package.json"),
    ("outside/linked/package.json", "/outside/linked/package.json"),
]


def fixture_inputs(directory):
    result = {}
    for source, guest in FILES:
        info = (directory / source).stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("fixture input is not a regular file")
        if os.name == "nt":
            if not info.st_mode & stat.S_IWRITE:
                raise ValueError("Windows fixture input is readonly")
            # NativeFs's established Windows regular-file guest mode is 0644.
            # operation.py requires the real Rust Host observation to agree.
            result[guest] = 0o644
        else:
            result[guest] = stat.S_IMODE(info.st_mode)
    if len(result) != 3 or any(mode != 0o644 for mode in result.values()):
        raise ValueError("fixture differs from Linux 0644 guest inputs")
    return result
