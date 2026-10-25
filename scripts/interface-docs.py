#!/usr/bin/env python3
"""Check the documentation against the code it describes.

- The command-line page lists exactly the options the parser accepts.
- The JavaScript page names everything index.d.ts declares, and its run
  options table lists exactly the run options.
- Every English page has a Japanese page with the same headings structure.
- Every link to a heading (`page#section`) names an id that page has.
"""

import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
CLI = ROOT / "crates/paludarium/src/cli.rs"
TYPES = ROOT / "packages/paludarium-wasm/index.d.ts"
LANGUAGES = ("guide", "ja/guide")
# The Japanese release page is a summary that links to the English one.
SUMMARIES = {"release.md"}

# The sources are read with regular expressions that assume rustfmt's layout
# and the one-member-per-line style of index.d.ts.
LAYOUT = "written in a form scripts/interface-docs.py does not read"


def need(where, found):
    """What one reading found, which must not be empty."""
    if not found:
        raise ValueError(f"{where}: nothing found; {LAYOUT}")
    return found


def between(text, start, end):
    """The text after the first `start` up to the next `end`."""
    begin = text.find(start)
    stop = text.find(end, begin + len(start)) if begin >= 0 else -1
    if stop < 0:
        raise ValueError(f"{start!r} ... {end!r} not found; {LAYOUT}")
    return text[begin + len(start) : stop]


def compare(where, what, expected, found):
    """Errors for each name in one set but not the other."""
    errors = [f"{where}: {what} `{name}` is missing" for name in sorted(expected - found)]
    errors += [f"{where}: {what} `{name}` does not exist" for name in sorted(found - expected)]
    return errors


def code_names(page):
    """The identifiers and option names inside the page's code spans and blocks."""
    text = page.read_text(encoding="utf-8")
    code = re.findall(r"```.*?```|`[^`\n]+`", text, re.DOTALL)
    return {name for span in code for name in re.findall(r"-{0,2}[\w-]+", span)}


def cli():
    source = CLI.read_text(encoding="utf-8")
    parser = between(source, "let program = loop {", "\n    };\n")
    options = need("parse()", set(re.findall(r'b"(-[\w-]*)"(?= \||\s*=>)', parser)))
    joined = need("parse() `=` forms", set(re.findall(r'starts_with\(b"(--[\w-]+=)"\)', parser)))
    named = options - {"--", "-h", "--help"}
    usage = need("USAGE", set(re.findall(r"\[(--[\w-]+)", between(source, "USAGE: &str", ";"))))
    module = between(source, "//! ```text", "//! ```")
    listed = need("the module documentation", set(re.findall(r"^//! +(--[\w-]+)", module, re.M)))
    errors = compare("cli.rs USAGE", "option", named, usage)
    errors += compare("cli.rs module documentation", "option", named, listed)
    for language in LANGUAGES:
        page = DOCS / language / "cli.md"
        where = page.relative_to(ROOT)
        text = page.read_text(encoding="utf-8")
        synopsis = set(re.findall(r"\[(--[\w-]+)", between(text, "```sh", "```")))
        errors += compare(f"{where} synopsis", "option", named, synopsis)
        bullets = re.findall(r"^- ((?:`-[^`]*`(?:, |、)?)+)", text, re.MULTILINE)
        found = {option for bullet in bullets for option in re.findall(r"`(-{1,2}[\w-]*)", bullet)}
        errors += compare(f"{where} list", "option", options, found)
        errors += [
            f"{where}: the form `{form}` is missing"
            for form in sorted(joined)
            if f"`{form}" not in text
        ]
    return errors


def interfaces(source):
    """Each interface and class of index.d.ts with its members and the
    members of the objects its methods take."""
    members = {}
    for name, parent, body in re.findall(
        r"^export (?:interface|class) (\w+)(?: extends (\w+))? \{(.*?)\}$", source, re.M | re.S
    ):
        body = re.sub(r"/\*\*.*?\*/", "", body, flags=re.S)
        own = set(re.findall(r"^\s*(?:readonly )?(\w+)\??[(:]", body, re.MULTILINE))
        objects = re.findall(r"^\s*\w+\(.*?\{([^}]*)\}", body, re.MULTILINE)
        inner = {member for fields in objects for member in re.findall(r"(\w+)\??:", fields)}
        members[name] = (parent, own, inner)
    return need("index.d.ts interfaces", members)


def javascript():
    source = TYPES.read_text(encoding="utf-8")
    members = interfaces(source)
    run_parent, run_own, _ = members["RunOptions"]
    run = run_own | members[run_parent][1]
    required = {name for _, own, inner in members.values() for name in own | inner}
    required |= set(re.findall(r"^export (?:function|class) (\w+)", source, re.MULTILINE))
    required |= set(re.findall(r'"([a-z][\w-]*)"', source))
    errors = []
    for language in LANGUAGES:
        page = DOCS / language / "javascript.md"
        where = page.relative_to(ROOT)
        tables = re.findall(r"(?:^\|[^\n]*\n)+", page.read_text(encoding="utf-8"), re.MULTILINE)
        table = [block for block in tables if "| `program` |" in block]
        if len(table) != 1:
            raise ValueError(f"{where}: no single run options table")
        rows = set(re.findall(r"^\| `(\w+)` \|", table[0], re.MULTILINE))
        errors += compare(f"{where} run options", "option", run, rows)
        missing = required - code_names(page)
        errors += [f"{where}: index.d.ts declares `{name}`" for name in sorted(missing)]
    return errors


def headings(page):
    """The levels of the page's headings, outside code blocks, in order."""
    text = re.sub(r"```.*?```", "", page.read_text(encoding="utf-8"), flags=re.DOTALL)
    return [len(mark) for mark in re.findall(r"^(#+) ", text, re.MULTILINE)]


def find(base, skip):
    return {
        page.relative_to(base)
        for page in base.rglob("*.md")
        if not any(part in skip for part in page.relative_to(base).parts)
    }


def slugify(title):
    """VitePress's slugify (@mdit-vue/shared), which decomposes the title as
    NFKD: a heading with a dakuten such as プ gets an id that a link written
    with the composed character does not match."""
    text = unicodedata.normalize("NFKD", title)
    text = re.sub(r"[\u0300-\u036f]", "", text)
    text = re.sub(r"[\u0000-\u001f]", "", text)
    text = re.sub(r"[\s~`!@#$%^&*()\-_+=\[\]{}|\\;:\"'\u201c\u201d\u2018\u2019<>,.?/]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return re.sub(r"^(\d)", r"_\1", text).lower()


def anchors(page):
    """The ids of the page's headings, as markdown-it-anchor gives them: an
    explicit `{#id}`, or the slug of the heading's text and inline code, with
    -1, -2 ... added to repeats."""
    text = re.sub(r"```.*?```", "", page.read_text(encoding="utf-8"), flags=re.DOTALL)
    ids = set()
    for title in re.findall(r"^#+ +(.*?) *$", text, re.MULTILINE):
        explicit = re.search(r"\{#([^}\s]+)\}$", title)
        if explicit:
            ids.add(explicit.group(1))
            continue
        title = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", title)
        title = re.sub(r"<[^>]+>|[*`\\]", "", title)
        slug = base = slugify(title)
        repeat = 1
        while slug in ids:
            slug, repeat = f"{base}-{repeat}", repeat + 1
        ids.add(slug)
    return ids


def links():
    """Errors for each link to a heading that its page does not have."""
    every = find(DOCS, {"node_modules", ".vitepress"})
    ids = {page.with_suffix(""): anchors(DOCS / page) for page in every}
    errors = []
    for page in sorted(every):
        text = re.sub(
            r"```.*?```|`[^`\n]+`", "", (DOCS / page).read_text(encoding="utf-8"), flags=re.DOTALL
        )
        targets = re.findall(r"\]\(\s*([^)\s]*#[^)\s]+)", text)
        targets += re.findall(r'href="([^"]*#[^"]+)"', text)
        for target in targets:
            path, fragment = target.split("#", 1)
            if re.match(r"[a-z]+:|//", path):
                continue
            if not path:
                linked = page.with_suffix("")
            elif path.startswith("/"):
                linked = Path(path.lstrip("/"))
            else:
                linked = Path(*(page.parent / path).parts)
            linked = Path(re.sub(r"\.(md|html)$", "", str(linked)))
            parts = []
            for part in linked.parts:
                if part == "..":
                    parts.pop() if parts else None
                elif part != ".":
                    parts.append(part)
            linked = Path(*parts) if parts else Path("index")
            if linked not in ids and linked / "index" in ids:
                linked = linked / "index"
            if linked not in ids:
                errors.append(f"docs/{page}: the link {target} names no page")
            elif unquote(fragment) not in ids[linked]:
                errors.append(f"docs/{page}: docs/{linked}.md has no heading #{fragment}")
    return errors


def pages():
    english = find(DOCS, {"ja", "node_modules", ".vitepress"})
    japanese = find(DOCS / "ja", {"node_modules"})
    errors = compare("docs/ja", "page", {str(p) for p in english}, {str(p) for p in japanese})
    for page in sorted(english & japanese):
        if str(page) in SUMMARIES:
            continue
        if headings(DOCS / page) != headings(DOCS / "ja" / page):
            errors.append(f"docs/{page} and docs/ja/{page} have different headings structures")
    return errors, len(english)


def main():
    try:
        errors = cli() + javascript() + links()
        page_errors, count = pages()
    except (ValueError, KeyError) as error:
        print(f"{error}", file=sys.stderr)
        return 1
    errors += page_errors
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(
        f"the CLI and JavaScript pages match the code; {count} pages have Japanese counterparts;"
        " every link to a heading resolves"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
