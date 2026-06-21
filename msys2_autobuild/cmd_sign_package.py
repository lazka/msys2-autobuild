import gzip
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .mtree import FileMetadata, MtreeEntry, parse_mtree_entries, patch_mtree_text

PACKAGE_METADATA_FILES = {
    ".BUILDINFO",
    ".Changelog",
    ".CHANGELOG",
    ".INSTALL",
    ".MTREE",
    ".PKGINFO",
}

def is_pe_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return False

            handle.seek(0x3C)
            pe_offset_bytes = handle.read(4)
            if len(pe_offset_bytes) != 4:
                return False

            pe_offset = int.from_bytes(pe_offset_bytes, "little")
            if pe_offset < 0x40:
                return False

            handle.seek(pe_offset)
            return handle.read(4) == b"PE\0\0"
    except OSError:
        return False


def update_pkginfo_size(pkginfo_text: str, size: int) -> str:
    lines = pkginfo_text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("size = "):
            lines[index] = f"size = {size}"
            new_text = "\n".join(lines)
            if pkginfo_text.endswith("\n"):
                new_text += "\n"
            return new_text

    raise SystemExit(".PKGINFO missing 'size = ...' entry")


def calculate_payload_size(
        entries: dict[str, Any],
        updated_sizes: dict[str, int] | None = None) -> int:
    updated_sizes = updated_sizes or {}
    total = 0
    for rel_path, entry in entries.items():
        first_component = PurePosixPath(rel_path).parts[0]
        if first_component in PACKAGE_METADATA_FILES:
            continue

        size_value = updated_sizes.get(rel_path, entry.attrs.get("size"))
        if size_value is None:
            continue
        total += int(size_value)

    return total


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_file_metadata(path: Path) -> FileMetadata:
    return FileMetadata(size=path.stat().st_size, sha256digest=sha256sum(path))


def set_mtime_from_entry(path: Path, entry: MtreeEntry | None) -> None:
    if entry is None or "time" not in entry.attrs:
        return
    timestamp = float(entry.attrs["time"])
    os.utime(path, (path.stat().st_atime, timestamp))


def iter_sign_batches(base_args: list[str], files: list[Path], max_chars: int = 28000) -> list[list[str]]:
    commands = []
    batch: list[str] = []
    base_length = sum(len(arg) + 1 for arg in base_args)
    current_length = base_length

    for path in files:
        path_arg = str(path)
        path_length = len(path_arg) + 1
        if batch and current_length + path_length > max_chars:
            commands.append(base_args + batch)
            batch = []
            current_length = base_length

        batch.append(path_arg)
        current_length += path_length

    if batch:
        commands.append(base_args + batch)

    return commands


def list_package_paths(root: Path) -> list[str]:
    paths = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort(key=lambda value: value.encode("utf-8"))
        filenames.sort(key=lambda value: value.encode("utf-8"))

        current_root = Path(dirpath)
        for name in dirnames:
            paths.append((current_root / name).relative_to(root).as_posix())
        for name in filenames:
            paths.append((current_root / name).relative_to(root).as_posix())

    return sorted(paths, key=lambda value: value.encode("utf-8"))


def sign_binary_files(files: list[Path], sign_tool: str, sign_options: list[str]) -> None:
    base_args = [sign_tool, "sign", *sign_options]
    for command in iter_sign_batches(base_args, files):
        subprocess.run(command, check=True)


def get_signable_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if is_pe_binary(path):
            files.append(path)
    return sorted(files)


def sign_extracted_package(root: Path, sign_tool: str, sign_options: list[str]) -> list[Path]:
    mtree_path = root / ".MTREE"
    pkginfo_path = root / ".PKGINFO"
    if not mtree_path.is_file() or not pkginfo_path.is_file():
        raise SystemExit("package root must contain .MTREE and .PKGINFO")

    mtree_file_stat = mtree_path.stat()
    mtree_text = gzip.decompress(mtree_path.read_bytes()).decode("utf-8")
    mtree_entries = parse_mtree_entries(mtree_text)

    signable_files = get_signable_files(root)
    if not signable_files:
        return []

    sign_binary_files(signable_files, sign_tool, sign_options)

    signed_updates: dict[str, FileMetadata] = {}
    updated_sizes: dict[str, int] = {}
    for path in signable_files:
        rel_path = path.relative_to(root).as_posix()
        entry = mtree_entries.get(rel_path)
        set_mtime_from_entry(path, entry)
        metadata = get_file_metadata(path)
        signed_updates[rel_path] = metadata
        updated_sizes[rel_path] = metadata.size

    payload_size = calculate_payload_size(mtree_entries, updated_sizes)
    pkginfo_text = pkginfo_path.read_text(encoding="utf-8")
    updated_pkginfo_text = update_pkginfo_size(pkginfo_text, payload_size)
    pkginfo_path.write_text(updated_pkginfo_text, encoding="utf-8", newline="\n")
    set_mtime_from_entry(pkginfo_path, mtree_entries.get(".PKGINFO"))

    signed_updates[".PKGINFO"] = get_file_metadata(pkginfo_path)
    updated_mtree_text = patch_mtree_text(mtree_text, signed_updates)
    mtree_path.write_bytes(gzip.compress(updated_mtree_text.encode("utf-8"), mtime=0))
    os.utime(mtree_path, (mtree_file_stat.st_atime, mtree_file_stat.st_mtime))
    return signable_files


def repack_package_tree(root: Path, output_path: Path) -> None:
    archive_entries = list_package_paths(root)
    with tempfile.TemporaryDirectory(prefix="sign-package-tar-") as tempdir:
        temp_tar = Path(tempdir) / "package.tar"
        files_from = "\0".join(archive_entries).encode("utf-8") + b"\0"
        subprocess.run([
            "bsdtar",
            "--no-fflags",
            "--no-read-sparse",
            "-cnf",
            str(temp_tar),
            "-C",
            str(root),
            "--null",
            "--files-from",
            "-",
        ], check=True, input=files_from)
        with output_path.open("wb") as handle:
            subprocess.run([
                "zstd", "-c", "-T0", "--ultra", "-20", str(temp_tar)
            ], check=True, stdout=handle)


def sign_package_archive(package_path: Path, sign_tool: str, sign_options: list[str]) -> int:
    if not package_path.name.endswith(".pkg.tar.zst"):
        raise SystemExit(f"unsupported package filename: {package_path}")

    # Rewriting the package would invalidate an existing detached package signature.
    detached_signature = Path(str(package_path) + ".sig")
    if detached_signature.exists():
        raise SystemExit(
            f"refusing to rewrite {package_path.name!r} while detached signature "
            f"{detached_signature.name!r} exists")

    with tempfile.TemporaryDirectory(prefix="sign-package-") as tempdir:
        root = Path(tempdir) / "pkg"
        root.mkdir()
        subprocess.run(["bsdtar", "-xf", str(package_path), "-C", str(root)], check=True)

        signed_files = sign_extracted_package(root, sign_tool, sign_options)
        if not signed_files:
            return 0

        fd, temp_output = tempfile.mkstemp(
            prefix=package_path.name + ".",
            suffix=".tmp",
            dir=str(package_path.parent),
        )
        os.close(fd)
        temp_output_path = Path(temp_output)
        try:
            repack_package_tree(root, temp_output_path)
            os.replace(temp_output_path, package_path)
        finally:
            temp_output_path.unlink(missing_ok=True)

        return len(signed_files)


def sign_package(args: Any) -> None:
    for tool in ["bsdtar", "zstd", args.sign_tool]:
        if shutil.which(tool) is None:
            raise SystemExit(f"required tool not found in PATH: {tool}")

    sign_options = []
    for flag, value in [
        ("--endpoint", args.endpoint),
        ("--account", args.account),
        ("--profile", args.profile),
        ("--oidc-client-id", args.oidc_client_id),
        ("--oidc-tenant-id", args.oidc_tenant_id),
    ]:
        if value is not None:
            sign_options.extend([flag, value])

    for package in args.packages:
        package_path = Path(package).resolve()
        if not package_path.is_file():
            raise SystemExit(f"package not found: {package}")

        signed_count = sign_package_archive(package_path, args.sign_tool, sign_options)
        if signed_count:
            print(f"Signed {signed_count} binaries in {package_path}")
        else:
            print(f"No PE binaries found in {package_path}")


def add_parser(subparsers: Any) -> None:
    sub = subparsers.add_parser(
        "sign-package",
        help="Sign binaries inside .pkg.tar.zst archives",
        allow_abbrev=False,
    )
    sub.add_argument("packages", nargs="+", help="Package archive(s) to update in place")
    sub.add_argument("--sign-tool", default="aas-sign", help="Signing executable to invoke")
    sub.add_argument("--endpoint")
    sub.add_argument("--account")
    sub.add_argument("--profile")
    sub.add_argument("--oidc-client-id")
    sub.add_argument("--oidc-tenant-id")
    sub.set_defaults(func=sign_package)
