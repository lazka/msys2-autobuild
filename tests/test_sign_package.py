import gzip
import hashlib
import os
from pathlib import Path

from msys2_autobuild.cmd_sign_package import (calculate_payload_size,
                                              is_pe_binary, list_package_paths,
                                              sign_extracted_package)
from msys2_autobuild.mtree import FileMetadata, parse_mtree_entries, patch_mtree_text


def make_pe_file(path: Path, payload: bytes = b"") -> None:
    data = bytearray(0x90)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data.extend(payload)
    path.write_bytes(data)


def sha256sum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_is_pe_binary(tmp_path: Path):
    pe_file = tmp_path / "app.exe"
    make_pe_file(pe_file, b"payload")
    text_file = tmp_path / "readme.txt"
    text_file.write_text("not a binary", encoding="utf-8")
    short_file = tmp_path / "short.exe"
    short_file.write_bytes(b"MZ")

    assert is_pe_binary(pe_file) is True
    assert is_pe_binary(text_file) is False
    assert is_pe_binary(short_file) is False


def test_parse_mtree_entries_unescapes_paths():
    mtree_text = "\n".join([
        "#mtree",
        "/set type=file uid=0 gid=0 mode=644",
        "./usr/bin/my\\040tool.exe time=11.0 size=20 sha256digest=oldbin",
        "./usr/bin/my\\\\tool.exe time=12.0 size=21 sha256digest=nextbin",
        "",
    ])

    entries = parse_mtree_entries(mtree_text)

    assert "usr/bin/my tool.exe" in entries
    assert entries["usr/bin/my tool.exe"].attrs["size"] == "20"
    assert "usr/bin/my\\tool.exe" in entries
    assert entries["usr/bin/my\\tool.exe"].attrs["size"] == "21"
    assert len(entries) == 2


def test_patch_mtree_text_updates_entries():
    mtree_text = "\n".join([
        "#mtree",
        "./.PKGINFO time=10.0 size=12 sha256digest=oldpkg",
        "./usr/bin/my-tool.exe time=11.0 size=20 sha256digest=oldbin",
        "",
    ])

    patched = patch_mtree_text(mtree_text, {
        ".PKGINFO": FileMetadata(size=44, sha256digest="newpkg"),
        "usr/bin/my-tool.exe": FileMetadata(size=32, sha256digest="newbin"),
    })
    entries = parse_mtree_entries(patched)

    assert entries[".PKGINFO"].attrs["size"] == "44"
    assert entries[".PKGINFO"].attrs["sha256digest"] == "newpkg"
    assert entries["usr/bin/my-tool.exe"].attrs["size"] == "32"
    assert entries["usr/bin/my-tool.exe"].attrs["sha256digest"] == "newbin"


def test_list_package_paths_is_sorted_and_includes_dotfiles(tmp_path: Path):
    (tmp_path / ".PKGINFO").write_text("pkgname = sample\n", encoding="utf-8")
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "b.exe").write_text("b", encoding="utf-8")
    (tmp_path / "usr" / "bin" / "a.exe").write_text("a", encoding="utf-8")

    assert list_package_paths(tmp_path) == [
        ".PKGINFO",
        "usr",
        "usr/bin",
        "usr/bin/a.exe",
        "usr/bin/b.exe",
    ]


def test_sign_extracted_package_updates_pkginfo_and_mtree(tmp_path: Path, monkeypatch):
    root = tmp_path
    usr_bin = root / "usr" / "bin"
    usr_share = root / "usr" / "share"
    usr_bin.mkdir(parents=True)
    usr_share.mkdir(parents=True)

    buildinfo_path = root / ".BUILDINFO"
    buildinfo_path.write_text("build info\n", encoding="utf-8")

    readme_path = usr_share / "readme.txt"
    readme_path.write_text("hello\n", encoding="utf-8")

    binary_path = usr_bin / "app.exe"
    make_pe_file(binary_path, b"unsigned")

    pkginfo_path = root / ".PKGINFO"
    original_payload_size = binary_path.stat().st_size + readme_path.stat().st_size
    pkginfo_path.write_text(
        "pkgname = sample\n"
        "pkgver = 1-1\n"
        f"size = {original_payload_size}\n",
        encoding="utf-8",
    )

    mtree_text = "\n".join([
        "#mtree",
        (
            f"./.BUILDINFO time=100.0 size={buildinfo_path.stat().st_size} "
            f"sha256digest={sha256sum(buildinfo_path)}"
        ),
        (
            f"./.PKGINFO time=101.0 size={pkginfo_path.stat().st_size} "
            f"sha256digest={sha256sum(pkginfo_path)}"
        ),
        "./usr time=102.0 type=dir",
        "./usr/bin time=103.0 type=dir",
        (
            f"./usr/bin/app.exe time=104.0 size={binary_path.stat().st_size} "
            f"sha256digest={sha256sum(binary_path)}"
        ),
        "./usr/share time=105.0 type=dir",
        (
            f"./usr/share/readme.txt time=106.0 size={readme_path.stat().st_size} "
            f"sha256digest={sha256sum(readme_path)}"
        ),
        "",
    ])
    mtree_path = root / ".MTREE"
    mtree_path.write_bytes(gzip.compress(mtree_text.encode("utf-8"), mtime=0))
    original_mtree_mtime = mtree_path.stat().st_mtime

    os.utime(binary_path, (binary_path.stat().st_atime, 104.0))
    os.utime(pkginfo_path, (pkginfo_path.stat().st_atime, 101.0))

    def fake_sign_binary_files(files, sign_tool, sign_options):
        assert sign_tool == "aas-sign"
        assert sign_options == []
        assert files == [binary_path]
        for file_path in files:
            with file_path.open("ab") as handle:
                handle.write(b"-signed")

    monkeypatch.setattr(
        "msys2_autobuild.cmd_sign_package.sign_binary_files",
        fake_sign_binary_files,
    )

    signed_files = sign_extracted_package(root, "aas-sign", [])

    assert signed_files == [binary_path]
    assert binary_path.stat().st_mtime == 104.0
    assert pkginfo_path.stat().st_mtime == 101.0
    assert mtree_path.stat().st_mtime == original_mtree_mtime

    updated_pkginfo = pkginfo_path.read_text(encoding="utf-8")
    new_payload_size = binary_path.stat().st_size + readme_path.stat().st_size
    assert f"size = {new_payload_size}" in updated_pkginfo

    updated_entries = parse_mtree_entries(gzip.decompress(mtree_path.read_bytes()).decode("utf-8"))
    assert updated_entries["usr/bin/app.exe"].attrs["size"] == str(binary_path.stat().st_size)
    assert updated_entries["usr/bin/app.exe"].attrs["sha256digest"] == sha256sum(binary_path)
    assert updated_entries[".PKGINFO"].attrs["size"] == str(pkginfo_path.stat().st_size)
    assert updated_entries[".PKGINFO"].attrs["sha256digest"] == sha256sum(pkginfo_path)
    assert calculate_payload_size(updated_entries) == new_payload_size
