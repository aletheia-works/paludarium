"""U11 fixture metadata; inode identity is normalized by first path."""

import base64
import hashlib
import os
import pathlib
import stat


def prepare_epoch_fixture(directory):
    paths = []
    for path in sorted(pathlib.Path(directory).rglob("*")):
        if path.is_file() and not path.is_symlink():
            os.utime(path, ns=(0, 0))
            paths.append(str(path.relative_to(directory)))
    return {"initial_regular_file_mtime_ns": 0, "paths": paths}


def snapshot_metadata(directory):
    directory = pathlib.Path(directory)
    result, identities = {}, {}
    for path in [directory, *sorted(directory.rglob("*"))]:
        relative = str(path.relative_to(directory))
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        row = {"mode": stat.S_IMODE(info.st_mode), "mtime_ns": info.st_mtime_ns}
        if kind == stat.S_IFDIR:
            row["kind"] = "directory"
        elif kind == stat.S_IFLNK:
            row.update(kind="symlink", target=str(path.readlink()))
        elif kind == stat.S_IFREG:
            content = path.read_bytes()
            identity = (info.st_dev, info.st_ino)
            row.update(
                kind="file",
                sha256=hashlib.sha256(content).hexdigest(),
                identity=identities.setdefault(identity, relative),
                links=info.st_nlink,
            )
            if len(content) <= 65536:
                row["content_base64"] = base64.b64encode(content).decode("ascii")
        else:
            raise ValueError("unsupported native fixture object: " + relative)
        result[relative] = row
    return result
