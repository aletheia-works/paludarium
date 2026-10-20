"""Automatic same-head release evidence for an untagged version on main.

release-evidence.yml runs this on every push to main of the upstream
repository. When tag v<version> of the workspace version already exists, it
does nothing. Otherwise, for the main head only, it waits for the ci.yml push
run, dispatches u12-quality.yml, u14-quality.yml and release-check.yml once
each (a run a person already dispatched for the head is reused, never
doubled, because acceptance.py accepts exactly one run per workflow), waits
for all of them, then dispatches u15-acceptance.yml once and waits for it.
Only when every run succeeded does it write ready=true, the version and the
head to GITHUB_OUTPUT; the workflow then creates the tag and the GitHub
release, which start publish.yml; it publishes without waiting for any
approval. A failed run is never dispatched again
(FR8.3 is measured once per head); the head then needs a person.

Publication is by Trusted Publishing only, so every package must already exist
on its registry without this version. A new package (it needs one publication
by hand before its Trusted Publisher can be registered) or a version already
partly published (the stopped publish job is re-run instead) stops it before
any dispatch.
"""
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import acceptance
import check
import policy

CI = 'ci.yml'
QUALITY = ('u12-quality.yml', 'u14-quality.yml', 'release-check.yml')
PRODUCER = 'u15-acceptance.yml'
APPEAR_SECONDS = 15 * 60
COMPLETE_SECONDS = 150 * 60
POLL_SECONDS = 60


class Stop(Exception):
    """Nothing to do for this push; not a failure."""


class GitHubApi(acceptance.GitHubApi):
    def post(self, route, body):
        request = urllib.request.Request('https://api.github.com/repos/' + policy.REPOSITORY + '/' + route,
                                         data=json.dumps(body).encode(), method='POST',
                                         headers={'Authorization': 'Bearer ' + self.token,
                                                  'Accept': 'application/vnd.github+json',
                                                  'Content-Type': 'application/json',
                                                  'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self.opener.open(request, timeout=60) as response:
                response.read()
        except urllib.error.HTTPError as error:
            raise ValueError('GitHub request refused: %d %s' % (error.code, route)) from error


class Waiter:
    def __init__(self, api, head, sleep=time.sleep, clock=time.monotonic):
        self.api, self.head, self.sleep, self.clock = api, head, sleep, clock

    def runs(self, workflow, event):
        rows = acceptance.listing(self.api, 'actions/workflows/%s/runs?head_sha=%s&event=%s' % (workflow, self.head, event),
                                  'workflow_runs')
        return [r for r in rows if acceptance.official(r, self.head)]

    def one(self, workflow, event):
        """The single official run of the workflow at head, waiting for it to appear."""
        deadline = self.clock() + APPEAR_SECONDS
        while True:
            found = self.runs(workflow, event)
            policy.require(len(found) <= 1, '%s: %d same-head %s runs (exactly one allowed)' % (workflow, len(found), event))
            if found:
                return found[0]
            policy.require(self.clock() < deadline, '%s: no %s run for %s appeared; main may have moved' % (workflow, event, self.head))
            self.sleep(POLL_SECONDS)

    def dispatch(self, workflow, inputs=None):
        """Reuse the head's dispatched run when it exists; otherwise dispatch exactly once."""
        if not self.runs(workflow, 'workflow_dispatch'):
            policy.require(main_head(self.api) == self.head, 'main moved before dispatching ' + workflow)
            self.api.post('actions/workflows/%s/dispatches' % workflow, dict(ref='main', inputs=inputs or {}))
        return self.one(workflow, 'workflow_dispatch')

    def succeeded(self, run):
        deadline = self.clock() + COMPLETE_SECONDS
        while run['status'] != 'completed':
            policy.require(self.clock() < deadline, '%s: run %d did not complete in time' % (run['path'], run['id']))
            self.sleep(POLL_SECONDS)
            run = self.api.get('actions/runs/%d' % run['id'])
        policy.require(run['conclusion'] == 'success', '%s: run %d concluded %s; not dispatched again for this head'
                       % (run['path'], run['id'], run['conclusion']))
        return run


def main_head(api):
    return api.get('commits/main')['sha']


def tag_exists(api, version):
    refs = api.get('git/matching-refs/tags/v' + version)
    return any(r.get('ref') == 'refs/tags/v' + version for r in refs)


def version_present(name, version):
    url = check.NPM_PACKAGE_URL if name == check.NPM_NAME else check.CRATES_API + name
    return check.registry_present(url + '/' + version)


def publishable(inv, presence=check.registry_presence, present=version_present):
    """ValueError unless every package exists on its registry without this version."""
    found = presence(inv['order'])
    new = sorted(set(found['checked']) - set(found['present']))
    policy.require(not new, 'not on a registry yet: %s; publish it once by hand and register its Trusted Publisher '
                   '(docs/release.md)' % ', '.join(new))
    partial = [n for n in found['checked'] if present(n, inv['version'])]
    policy.require(not partial, '%s already on a registry: %s; re-run the stopped publish job instead'
                   % (inv['version'], ', '.join(partial)))


def produce(api, root, head, presence=check.registry_presence, present=version_present,
            sleep=time.sleep, clock=time.monotonic):
    inv = policy.inventory(root)
    version = inv['version']
    policy.require(version != '0.0.0', 'release version not decided')
    if tag_exists(api, version):
        raise Stop('v%s is already tagged' % version)
    if main_head(api) != head:
        raise Stop('%s is no longer the main head' % head)
    publishable(inv, presence, present)
    waiter = Waiter(api, head, sleep, clock)
    runs = [waiter.one(CI, 'push')] + [waiter.dispatch(w) for w in QUALITY]
    for run in runs:
        waiter.succeeded(run)
    waiter.succeeded(waiter.dispatch(PRODUCER))
    return dict(ready='true', version=version, head=head)


def main(environ=None, api=None, **kwargs):
    env = os.environ if environ is None else environ
    policy.require(env.get('GITHUB_REPOSITORY') == policy.REPOSITORY, 'release evidence runs only in ' + policy.REPOSITORY)
    policy.require(env.get('GITHUB_REF') == 'refs/heads/main', 'release evidence runs only for main')
    head = env.get('GITHUB_SHA', '')
    policy.require(bool(acceptance.HEAD.fullmatch(head)), 'invalid head')
    api = api or GitHubApi(env.get('GH_TOKEN') or env.get('GITHUB_TOKEN'))
    try:
        result = produce(api, Path(__file__).resolve().parents[2], head, **kwargs)
    except Stop as stop:
        print('nothing to do: %s' % stop)
        result = dict(ready='false')
    output = env.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a') as f:
            f.writelines('%s=%s\n' % item for item in sorted(result.items()))
    print(json.dumps(result))
    return result


if __name__ == '__main__':
    main()
