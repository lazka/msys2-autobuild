from dataclasses import dataclass


@dataclass
class MtreeEntry:
    line_index: int
    path: str
    attrs: dict[str, str]


@dataclass
class FileMetadata:
    size: int
    sha256digest: str


def unescape_mtree_path(value: str) -> str:
    result = []
    idx = 0
    while idx < len(value):
        if value[idx] != "\\":
            result.append(value[idx])
            idx += 1
            continue

        octal = value[idx + 1:idx + 4]
        if len(octal) == 3 and all(ch in "01234567" for ch in octal):
            result.append(chr(int(octal, 8)))
            idx += 4
            continue

        if idx + 1 < len(value):
            result.append(value[idx + 1])
            idx += 2
        else:
            result.append("\\")
            idx += 1

    return "".join(result)


def parse_mtree_entries(mtree_text: str) -> dict[str, MtreeEntry]:
    entries: dict[str, MtreeEntry] = {}
    for line_index, line in enumerate(mtree_text.splitlines()):
        # We only patch explicit file entries, so /set inheritance is not needed here.
        if not line.startswith("./"):
            continue

        parts = line.split()
        attrs = {}
        for token in parts[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            attrs[key] = value

        path = unescape_mtree_path(parts[0][2:])
        entries[path] = MtreeEntry(line_index=line_index, path=path, attrs=attrs)

    return entries


def patch_mtree_text(mtree_text: str, updates: dict[str, FileMetadata]) -> str:
    lines = mtree_text.splitlines()
    entries = parse_mtree_entries(mtree_text)

    for rel_path, metadata in updates.items():
        if rel_path not in entries:
            raise Exception(f"mtree entry for {rel_path!r} not found")

        tokens = lines[entries[rel_path].line_index].split()
        new_tokens = [tokens[0]]
        seen = set()
        for token in tokens[1:]:
            if token.startswith("size="):
                token = f"size={metadata.size}"
                seen.add("size")
            elif token.startswith("sha256digest="):
                token = f"sha256digest={metadata.sha256digest}"
                seen.add("sha256digest")
            new_tokens.append(token)

        if "size" not in seen:
            raise Exception(f"mtree entry for {rel_path!r} missing size")
        if "sha256digest" not in seen:
            raise Exception(f"mtree entry for {rel_path!r} missing sha256digest")

        lines[entries[rel_path].line_index] = " ".join(new_tokens)

    new_text = "\n".join(lines)
    if mtree_text.endswith("\n"):
        new_text += "\n"
    return new_text
