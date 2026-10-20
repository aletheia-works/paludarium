"""release-evidence.yml driver tests. The GitHub API and the registries are
replaced by in-memory fakes; nothing reaches the network, and a passing test
is not evidence that any real run, tag or registry state exists."""
import itertools
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import check  # noqa: E402
import evidence as E  # noqa: E402
import policy  # noqa: E402

HEAD = 'a' * 40
OTHER = 'c' * 40
VERSION = policy.inventory(ROOT)['version']


def absent(order):
    return dict(absent=True, present=[])


class FakeGitHub:
    def __init__(self, conclusion='success'):
        self.main = HEAD
        self.tags = []
        self.runs = []
        self.posts = []
        self.conclusion = conclusion
        self.ids = itertools.count(1)
        self.add('ci.yml', 'push')

    def add(self, workflow, event, head=HEAD, status='queued'):
        run = dict(id=next(self.ids), path='.github/workflows/' + workflow, head_sha=head, event=event,
                   head_branch='main', status=status, conclusion=None,
                   repository=dict(full_name=policy.REPOSITORY), head_repository=dict(full_name=policy.REPOSITORY))
        self.runs.append(run)
        return run

    def get(self, route):
        if route == 'commits/main':
            return dict(sha=self.main)
        if route.startswith('git/matching-refs/tags/'):
            return [dict(ref='refs/tags/' + t) for t in self.tags if t.startswith(route.rsplit('/', 1)[1])]
        match = re.fullmatch(r'actions/workflows/([^/]+)/runs\?head_sha=(\w+)&event=(\w+)&per_page=100', route)
        if match:
            rows = [r for r in self.runs if r['path'].endswith('/' + match[1]) and r['head_sha'] == match[2]
                    and r['event'] == match[3]]
            return dict(total_count=len(rows), workflow_runs=[dict(r) for r in rows])
        match = re.fullmatch(r'actions/runs/(\d+)', route)
        if match:
            run = next(r for r in self.runs if r['id'] == int(match[1]))
            run.update(status='completed', conclusion=self.conclusion)
            return dict(run)
        raise AssertionError('unexpected route ' + route)

    def post(self, route, body):
        self.posts.append((route, body))
        workflow = re.fullmatch(r'actions/workflows/([^/]+)/dispatches', route)[1]
        self.add(workflow, 'workflow_dispatch', head=self.main)


class Clock:
    def __init__(self):
        self.now = 0

    def sleep(self, seconds):
        self.now += seconds

    def __call__(self):
        return self.now


def produce(api, registries=absent):
    clock = Clock()
    return E.produce(api, ROOT, HEAD, absent=registries, sleep=clock.sleep, clock=clock)


class Evidence(unittest.TestCase):
    def test_untagged_head_dispatches_each_run_once_then_is_ready(self):
        api = FakeGitHub()
        self.assertEqual(produce(api), dict(ready='true', version=VERSION, head=HEAD))
        self.assertEqual([p[0] for p in api.posts], ['actions/workflows/%s/dispatches' % w for w in
                                                      ('u12-quality.yml', 'u14-quality.yml', 'release-check.yml', 'u15-acceptance.yml')])
        self.assertEqual(api.posts[-1][1], dict(ref='main', inputs=dict(first_publication='true')))
        self.assertTrue(all(p[1]['ref'] == 'main' for p in api.posts))

    def test_tagged_version_does_nothing(self):
        api = FakeGitHub()
        api.tags.append('v' + VERSION)
        with self.assertRaisesRegex(E.Stop, 'already tagged'):
            produce(api)
        self.assertEqual(api.posts, [])

    def test_a_longer_tag_with_the_same_prefix_is_not_the_version_tag(self):
        api = FakeGitHub()
        api.tags.append('v' + VERSION + '1')
        self.assertFalse(E.tag_exists(api, VERSION))

    def test_head_that_is_no_longer_main_does_nothing(self):
        api = FakeGitHub()
        api.main = OTHER
        with self.assertRaisesRegex(E.Stop, 'no longer the main head'):
            produce(api)
        self.assertEqual(api.posts, [])

    def test_present_registry_stops_before_any_dispatch(self):
        api = FakeGitHub()
        with self.assertRaisesRegex(ValueError, 'trusted_publishers_registered=true by hand'):
            produce(api, lambda order: dict(absent=False, present=['paludarium']))
        self.assertEqual(api.posts, [])

    def test_a_run_a_person_already_dispatched_is_reused(self):
        api = FakeGitHub()
        api.add('u12-quality.yml', 'workflow_dispatch')
        produce(api)
        self.assertNotIn('actions/workflows/u12-quality.yml/dispatches', [p[0] for p in api.posts])
        self.assertEqual(len([r for r in api.runs if r['path'].endswith('/u12-quality.yml')]), 1)

    def test_two_runs_of_one_workflow_are_refused(self):
        api = FakeGitHub()
        api.add('u14-quality.yml', 'workflow_dispatch')
        api.add('u14-quality.yml', 'workflow_dispatch')
        with self.assertRaisesRegex(ValueError, 'exactly one allowed'):
            produce(api)

    def test_failed_run_stops_without_acceptance_or_redispatch(self):
        api = FakeGitHub(conclusion='failure')
        with self.assertRaisesRegex(ValueError, 'concluded failure; not dispatched again'):
            produce(api)
        self.assertNotIn('actions/workflows/u15-acceptance.yml/dispatches', [p[0] for p in api.posts])
        self.assertEqual(len(api.posts), 3)

    def test_run_that_never_appears_is_refused(self):
        api = FakeGitHub()
        api.runs.clear()
        with self.assertRaisesRegex(ValueError, 'ci.yml: no push run'):
            produce(api)

    def test_main_moving_before_a_dispatch_is_refused(self):
        api = FakeGitHub()
        original = api.get

        def moving(route):
            if route.startswith('actions/workflows/u14-quality.yml/'):
                api.main = OTHER
            return original(route)
        api.get = moving
        with self.assertRaisesRegex(ValueError, 'main moved before dispatching u14-quality.yml'):
            produce(api)

    def test_run_that_never_completes_is_refused(self):
        api = FakeGitHub()
        api.get = lambda route, original=api.get: (
            dict(original(route), status='in_progress') if route.startswith('actions/runs/') else original(route))
        with self.assertRaisesRegex(ValueError, 'did not complete in time'):
            produce(api)

    def test_main_writes_outputs_and_refuses_forks_and_other_refs(self):
        env = dict(GITHUB_REPOSITORY=policy.REPOSITORY, GITHUB_REF='refs/heads/main', GITHUB_SHA=HEAD)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            api = FakeGitHub()
            api.tags.append('v' + VERSION)
            self.assertEqual(E.main(dict(env, GITHUB_OUTPUT=str(output)), api), dict(ready='false'))
            self.assertEqual(output.read_text(), 'ready=false\n')
            clock = Clock()
            E.main(dict(env, GITHUB_OUTPUT=str(output)), FakeGitHub(), absent=absent, sleep=clock.sleep, clock=clock)
            self.assertEqual(output.read_text().splitlines()[1:], ['head=' + HEAD, 'ready=true', 'version=' + VERSION])
        for bad in (dict(GITHUB_REPOSITORY='Marukome0743/paludarium'), dict(GITHUB_REF='refs/heads/other'), dict(GITHUB_SHA='x')):
            with self.assertRaises(ValueError):
                E.main(dict(env, **bad), FakeGitHub())

    def test_workflow_is_pinned_and_tags_with_the_app_token(self):
        text = (ROOT / '.github/workflows/release-evidence.yml').read_text()
        actions = re.findall(r'uses:\s+([^\s#]+)', text)
        self.assertTrue(actions and all(re.fullmatch(r'[^@]+@[0-9a-f]{40}', a) for a in actions))
        self.assertEqual(text.count('persist-credentials: false'), 2)
        self.assertIn('vars.RELEASE_AUTOMATION_ENABLED', text)
        self.assertIn('GH_TOKEN: ${{ steps.app-token.outputs.token }}', text)
        self.assertIn('--target "$HEAD_SHA"', text)
        self.assertEqual(check.validate(ROOT)['validated'], True)


if __name__ == '__main__':
    unittest.main()
