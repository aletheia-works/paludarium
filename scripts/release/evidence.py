"""Automatic same-head release evidence for an untagged version on main.

The evidence job of publish.yml runs this on every push to main of the
upstream repository. When tag v<version> of the workspace version already
exists, it does nothing. Otherwise, for the main head only, it waits for the
ci.yml push run, dispatches macos-quality.yml, quality.yml and
release-check.yml once each (a run a person already dispatched for the head
is reused, never doubled, because acceptance.py accepts exactly one run per
workflow), waits for all of them, then dispatches release-acceptance.yml once
and waits for it. Only when every run succeeded does it write ready=true,
the version and the head to GITHUB_OUTPUT; publish.yml then publishes that
head and creates the tag and the GitHub release last, so a version that was
not published never gets a tag. A failed run is never dispatched again
(performance is measured once per head); the head then needs a person.

Publication is by Trusted Publishing only, so every package must already exist
on its registry without this version. A new package (it needs one publication
by hand before its Trusted Publisher can be registered) or a version already
partly published (the stopped publish job is re-run instead) stops it before
any dispatch.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

import acceptance
import check
import policy

CI = "ci.yml"
QUALITY = ("macos-quality.yml", "quality.yml", "release-check.yml")
PRODUCER = "release-acceptance.yml"
APPEAR_SECONDS = 15 * 60
COMPLETE_SECONDS = 150 * 60
POLL_SECONDS = 60
RELEASE_BRANCH = "release-please--branches--main--components--paludarium"
RELEASE_BOT = "aletheia-works-bot[bot]"
PENDING = "autorelease: pending"


class Stop(Exception):
    """Nothing to do for this push; not a failure."""


class GitHubApi(acceptance.GitHubApi):
    def post(self, route, body):
        request = urllib.request.Request(
            "https://api.github.com/repos/" + policy.REPOSITORY + "/" + route,
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                response.read()
        except urllib.error.HTTPError as error:
            raise ValueError(f"GitHub request refused: {error.code:d} {route}") from error


class Waiter:
    def __init__(self, api, head, sleep=time.sleep, clock=time.monotonic):
        self.api, self.head, self.sleep, self.clock = api, head, sleep, clock

    def runs(self, workflow, event):
        rows = acceptance.listing(
            self.api,
            f"actions/workflows/{workflow}/runs?head_sha={self.head}&event={event}",
            "workflow_runs",
        )
        return [r for r in rows if acceptance.official(r, self.head)]

    def one(self, workflow, event):
        """The single official run of the workflow at head, waiting for it to appear."""
        deadline = self.clock() + APPEAR_SECONDS
        while True:
            found = self.runs(workflow, event)
            policy.require(
                len(found) <= 1,
                f"{workflow}: {len(found):d} same-head {event} runs (exactly one allowed)",
            )
            if found:
                return found[0]
            policy.require(
                self.clock() < deadline,
                f"{workflow}: no {event} run for {self.head} appeared; main may have moved",
            )
            self.sleep(POLL_SECONDS)

    def dispatch(self, workflow, inputs=None):
        """Reuse the head's dispatched run when it exists; otherwise dispatch exactly once."""
        if not self.runs(workflow, "workflow_dispatch"):
            policy.require(
                main_head(self.api) == self.head, "main moved before dispatching " + workflow
            )
            self.api.post(
                f"actions/workflows/{workflow}/dispatches",
                dict(ref="main", inputs=inputs or {}),
            )
        return self.one(workflow, "workflow_dispatch")

    def succeeded(self, run):
        deadline = self.clock() + COMPLETE_SECONDS
        while run["status"] != "completed":
            policy.require(
                self.clock() < deadline,
                "{}: run {:d} did not complete in time".format(run["path"], run["id"]),
            )
            self.sleep(POLL_SECONDS)
            run = self.api.get("actions/runs/{:d}".format(run["id"]))
        policy.require(
            run["conclusion"] == "success",
            "{}: run {:d} concluded {}; not dispatched again for this head".format(
                run["path"], run["id"], run["conclusion"]
            ),
        )
        return run


def main_head(api):
    return api.get("commits/main")["sha"]


def tag_exists(api, version):
    refs = api.get("git/matching-refs/tags/v" + version)
    return any(r.get("ref") == "refs/tags/v" + version for r in refs)


def version_present(name, version):
    if name == check.JSR_KEY:
        return check.registry_present(check.JSR_PACKAGE_URL + "/" + version + "_meta.json")
    url = check.NPM_PACKAGE_URL if name == check.NPM_NAME else check.CRATES_API + name
    return check.registry_present(url + "/" + version)


def publishable(inv, presence=check.registry_presence, present=version_present):
    """ValueError unless every package exists on its registry without this version."""
    found = presence(inv["order"])
    new = sorted(set(found["checked"]) - set(found["present"]))
    policy.require(
        not new,
        "not on a registry yet: {}; publish it once by hand and register its Trusted Publisher, "
        "or create the JSR package and link it to the repository (docs/release.md)".format(
            ", ".join(new)
        ),
    )
    partial = [n for n in found["checked"] if present(n, inv["version"])]
    policy.require(
        not partial,
        "{} already on a registry: {}; re-run the stopped publish job instead".format(
            inv["version"], ", ".join(partial)
        ),
    )


def produce(
    api,
    root,
    head,
    presence=check.registry_presence,
    present=version_present,
    sleep=time.sleep,
    clock=time.monotonic,
):
    inv = policy.inventory(root)
    version = inv["version"]
    policy.require(version != "0.0.0", "release version not decided")
    if tag_exists(api, version):
        raise Stop(f"v{version} is already tagged")
    if main_head(api) != head:
        raise Stop(f"{head} is no longer the main head")
    publishable(inv, presence, present)
    waiter = Waiter(api, head, sleep, clock)
    runs = [waiter.one(CI, "push")] + [waiter.dispatch(w) for w in QUALITY]
    for run in runs:
        waiter.succeeded(run)
    waiter.succeeded(waiter.dispatch(PRODUCER))
    return dict(ready="true", version=version, head=head)


def release_notes(text, version):
    """The release notes section of version, without its heading.

    Release Please writes `## 0.1.0 (date)` for a first release and
    `## [0.1.1](compare link) (date)` once a previous tag exists. In a release
    PR body the section ends at the `---` line before the footer.
    """
    lines = text.splitlines()
    starts = [
        i
        for i, line in enumerate(lines)
        if line.startswith(f"## {version} ") or line.startswith(f"## [{version}](")
    ]
    policy.require(
        len(starts) == 1,
        f"release notes have {len(starts):d} sections for {version} (exactly one required)",
    )
    body = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("## ") or line == "---":
            break
        body.append(line)
    text = "\n".join(body).strip()
    policy.require(bool(text), f"release notes section for {version} is empty")
    return text + "\n"


# Release Please's default changelog sections, in its order; other types are
# hidden from the notes, but a breaking change of any type is listed first.
BREAKING = "⚠ BREAKING CHANGES"
SECTIONS = {
    "feat": "Features",
    "fix": "Bug Fixes",
    "perf": "Performance Improvements",
    "revert": "Reverts",
}
SUBJECT = re.compile(
    r"(?P<type>[a-z]+)(?:\((?P<scope>[^()]+)\))?(?P<breaking>!)?: "
    r"(?P<text>.+?)(?: \(#(?P<pr>\d+)\))?"
)
FOOTER = re.compile(r"^BREAKING[ -]CHANGE: (?P<note>.+)$", re.M)
COMPARE_LIMIT = 250


def entries(sha, message):
    """The notes lines Release Please writes for a commit, each with its
    section: one in the section of its type, and for a breaking change (`!`,
    or a `BREAKING CHANGE:` footer) its note, without links, in BREAKING."""
    subject = message.split("\n", 1)[0].strip()
    found = SUBJECT.fullmatch(subject)
    if not found:
        return []
    scope = "**{}:** ".format(found["scope"]) if found["scope"] else ""
    lines = []
    footer = FOOTER.search(message, len(subject))
    if found["breaking"] or footer:
        lines.append((BREAKING, "* " + scope + (footer["note"] if footer else found["text"])))
    if found["type"] in SECTIONS:
        url = "https://github.com/" + policy.REPOSITORY
        line = "* " + scope + found["text"]
        if found["pr"]:
            line += " ([#{0}]({1}/issues/{0}))".format(found["pr"], url)
        line += f" ([{sha[:7]}]({url}/commit/{sha}))"
        lines.append((SECTIONS[found["type"]], line))
    return lines


def with_later_commits(notes, commits):
    """notes with the commits main gained after the release PR was merged.

    Each goes at the end of its section, which is added in Release Please's
    order when the notes have none yet. Sections are apart by two blank
    lines, as Release Please writes them.
    """
    added = {}
    for commit in commits:
        for title, line in entries(commit["sha"], commit["commit"]["message"]):
            added.setdefault(title, []).append(line)
    if not added:
        return notes
    # [title, lines] for each section, the title None for any lines before
    # the first heading.
    blocks = [[None, []]]
    for line in notes.rstrip("\n").split("\n"):
        if line.startswith("### "):
            blocks.append([line[4:], []])
        else:
            blocks[-1][1].append(line)
    order = [BREAKING, *SECTIONS.values()]
    for title in order:
        if title not in added:
            continue
        block = next((b for b in blocks if b[0] == title), None)
        if block is None:
            block = [title, [""]]
            later = [i for i, b in enumerate(blocks) if b[0] in order[order.index(title) + 1 :]]
            blocks.insert(later[0] if later else len(blocks), block)
        while block[1] and block[1][-1] == "":
            block[1].pop()
        block[1].extend(added[title])
    parts = ["\n".join(lines).strip("\n") for title, lines in blocks if title is None]
    parts = [p for p in parts if p]
    parts += [
        "### {}\n\n{}".format(title, "\n".join(lines).strip("\n"))
        for title, lines in blocks
        if title
    ]
    return "\n\n\n".join(parts) + "\n"


def release_pr_notes(api, head, version):
    """The notes of version from the body of its merged release PR.

    Release Please writes no CHANGELOG.md (skip-changelog); the release PR body
    holds the same section. Exactly one merged release PR from the bot on the
    release-please branch may still be pending, and head must contain its
    merge commit. Main may have moved on after the release PR was merged (when
    an earlier Publish run stopped); the commits since then are released too,
    so they are added to the notes, as Release Please would have listed them.
    """
    owner = policy.REPOSITORY.split("/")[0]
    pulls = api.get(f"pulls?state=closed&base=main&head={owner}:{RELEASE_BRANCH}&per_page=100")
    policy.require(
        isinstance(pulls, list) and len(pulls) < 100, "release PR listing incomplete or paginated"
    )
    pending = [
        p
        for p in pulls
        if p.get("merged_at")
        and p["user"]["login"] == RELEASE_BOT
        and p["head"]["repo"]["full_name"] == policy.REPOSITORY
        and PENDING in {label["name"] for label in p["labels"]}
    ]
    policy.require(
        len(pending) == 1,
        f"{len(pending):d} merged release PRs are pending (exactly one required)",
    )
    merge = pending[0]["merge_commit_sha"]
    compare = api.get(f"compare/{merge}...{head}")
    policy.require(
        compare["status"] in ("ahead", "identical"),
        "release PR #{:d} merge commit is not in {}".format(pending[0]["number"], head),
    )
    commits = compare.get("commits") or []
    policy.require(
        len(commits) == compare.get("ahead_by", 0) and len(commits) < COMPARE_LIMIT,
        f"commits after the release PR incomplete: {len(commits):d} listed",
    )
    return with_later_commits(release_notes(pending[0]["body"] or "", version), commits)


def main(environ=None, api=None, **kwargs):
    env = os.environ if environ is None else environ
    policy.require(
        env.get("GITHUB_REPOSITORY") == policy.REPOSITORY,
        "release evidence runs only in " + policy.REPOSITORY,
    )
    policy.require(
        env.get("GITHUB_REF") == "refs/heads/main", "release evidence runs only for main"
    )
    head = env.get("GITHUB_SHA", "")
    policy.require(bool(acceptance.HEAD.fullmatch(head)), "invalid head")
    api = api or GitHubApi(env.get("GH_TOKEN") or env.get("GITHUB_TOKEN"))
    try:
        result = produce(api, Path(__file__).resolve().parents[2], head, **kwargs)
    except Stop as stop:
        print(f"nothing to do: {stop}")
        result = dict(ready="false")
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as f:
            f.writelines("{}={}\n".format(*item) for item in sorted(result.items()))
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    import sys

    if sys.argv[1:2] == ["notes"]:
        # publish.yml (tag job): evidence.py notes <version> <head> > release-notes.md
        version, head = sys.argv[2:4]
        policy.require(bool(acceptance.HEAD.fullmatch(head)), "invalid head")
        api = GitHubApi(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
        sys.stdout.write(release_pr_notes(api, head, version))
    else:
        main()
