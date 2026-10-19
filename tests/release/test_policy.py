import copy,sys,unittest,tempfile,shutil,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/release'))
import policy

def valid():
    inv=policy.inventory(ROOT);inv['version']='0.1.0';head='a'*40
    state=dict(repository=policy.REPOSITORY,tag='v0.1.0',commit=dict(sha=head,commit=dict(verification=dict(verified=True))),
       main_compare=dict(base_commit=dict(sha=head),status='ahead'),
       quality=[dict(purpose=k,repository=policy.REPOSITORY,head_sha=head,status='completed',conclusion='success',id=i+1) for i,k in enumerate(sorted(policy.REQUIRED))],
       acceptance=[dict(id=k,head=head,passed=True,artifact_sha256='b'*64) for k in sorted(policy.ACCEPTANCE)],
       environment=dict(name='release',can_admins_bypass=False,protection_rules=[dict(type='required_reviewers',prevent_self_review=True,reviewers=[dict(type='User',reviewer=dict(id=1))])]),
       trusted_publishers_registered=True,human_approved_head=head)
    return state,inv

class PolicyTests(unittest.TestCase):
    def setUp(self):self.s,self.i=valid()
    def reject(self):
        with self.assertRaises(ValueError):policy.release_gate(self.s,self.i)
    def test_valid_schema(self):self.assertTrue(policy.release_gate(self.s,self.i)['eligible'])
    def test_actual_inventory(self):
        self.assertEqual(len(self.i['packages']),11);self.assertEqual(len(self.i['private']),2)
        self.assertLess(self.i['order'].index('paludarium-types'),self.i['order'].index('paludarium-runtime'))
    def test_shell_tag(self):self.s['tag']='v0.1.0;evil';self.reject()
    def test_undecided_version(self):self.i['version']='0.0.0';self.reject()
    def test_version_mismatch(self):self.s['tag']='v0.2.0';self.reject()
    def test_wrong_repo(self):self.s['repository']='attacker/paludarium';self.reject()
    def test_wrong_head(self):self.s['quality'][0]['head_sha']='c'*40;self.reject()
    def test_unfinished(self):self.s['quality'][0]['status']='in_progress';self.reject()
    def test_failed(self):self.s['quality'][0]['conclusion']='failure';self.reject()
    def test_missing(self):self.s['quality'].pop();self.reject()
    def test_unsigned(self):self.s['commit']['commit']['verification']['verified']=False;self.reject()
    def test_unapproved(self):self.s['human_approved_head']=None;self.reject()
    def test_no_environment(self):self.s['environment']={};self.reject()
    def test_admin_bypass(self):self.s['environment']['can_admins_bypass']=True;self.reject()
    def test_unregistered(self):self.s['trusted_publishers_registered']=False;self.reject()
    def test_cycle(self):
        with self.assertRaises(ValueError):policy.dependency_order({'a':dict(dependencies={'b':'1'}),'b':dict(dependencies={'a':'1'})})
    def test_unknown_dependency(self):
        with self.assertRaises(ValueError):policy.dependency_order({'a':dict(dependencies={'missing':'1'})})
    def test_main_unreachable(self):self.s['main_compare']['status']='diverged';self.reject()
    def test_acceptance_missing(self):self.s['acceptance'].pop();self.reject()
    # Step14b (Q3): self-review prevention is no longer required.
    def test_self_review_allowed(self):
        rule=self.s['environment']['protection_rules'][0]
        for value in (False,None):
            with self.subTest(value):
                rule['prevent_self_review']=value;self.assertTrue(policy.release_gate(self.s,self.i)['eligible'])
        del rule['prevent_self_review'];self.assertTrue(policy.protected_environment(self.s['environment']))
    def test_required_reviewers_still_required(self):
        self.s['environment']['protection_rules'][0]['reviewers']=[];self.reject()
        self.s['environment']['protection_rules']=[dict(type='wait_timer',wait_timer=5)];self.reject()
    def test_admin_bypass_unknown(self):del self.s['environment']['can_admins_bypass'];self.reject()
    # Step14b (Q4): OIDC normally; the scoped token only for a verified first publication.
    def test_oidc_mode(self):self.assertEqual(policy.release_gate(self.s,self.i)['authentication'],'oidc')
    def first(self,**fields):self.s.update(dict(trusted_publishers_registered=False,first_publication=True),**fields)
    def test_first_publication_absent_allowed(self):
        self.first(registries_absent=True)
        self.assertEqual(policy.release_gate(self.s,self.i)['authentication'],'first-publication-token')
    def test_first_publication_existing_rejected(self):
        self.first(registries_absent=False)
        with self.assertRaisesRegex(ValueError,'trusted publishers unregistered'):policy.release_gate(self.s,self.i)
    def test_first_publication_unchecked_rejected(self):
        self.first();self.reject()
        self.first(registries_absent='true');self.reject()
    def test_no_declaration_rejected(self):
        self.s['trusted_publishers_registered']=False;self.s['registries_absent']=True
        with self.assertRaisesRegex(ValueError,'trusted publishers'):policy.release_gate(self.s,self.i)
    # Step17 (R-16): only the live-verified resume flag lets a stopped first publication continue.
    def test_first_publication_verified_resume_allowed(self):
        self.first(registries_absent=False,registry_resume_verified=True)
        self.assertEqual(policy.release_gate(self.s,self.i)['authentication'],'first-publication-token')
    def test_resume_flag_needs_declaration_and_exact_true(self):
        self.first(registries_absent=False,registry_resume_verified='true');self.reject()
        self.s.update(first_publication=False,registry_resume_verified=True)
        with self.assertRaisesRegex(ValueError,'trusted publishers unregistered'):policy.release_gate(self.s,self.i)
    def test_conflicting_declarations_rejected(self):
        self.s.update(first_publication=True,registries_absent=True)
        with self.assertRaisesRegex(ValueError,'conflicting'):policy.release_gate(self.s,self.i)
    def inherited_dependency(self,field):
        with tempfile.TemporaryDirectory(dir=ROOT/'target/u15') as directory:
            root=Path(directory);workspace=(ROOT/'Cargo.toml').read_text()
            workspace=workspace.replace('paludarium-types = { path =', 'paludarium-types = { '+field+', path =',1)
            (root/'Cargo.toml').write_text(workspace)
            members=tomllib.loads(workspace)['workspace']['members']
            for member in members:
                p=root/member;p.mkdir(parents=True);shutil.copyfile(ROOT/member/'Cargo.toml',p/'Cargo.toml')
            p=root/'packages/paludarium-wasm';p.mkdir(parents=True);shutil.copyfile(ROOT/'packages/paludarium-wasm/package.json',p/'package.json')
            with self.assertRaisesRegex(ValueError,'non-crates.io'):policy.inventory(root)
    def test_inherited_git_rejected(self):self.inherited_dependency('git = "https://example.invalid/repo"')
    def test_inherited_registry_rejected(self):self.inherited_dependency('registry = "untrusted"')
    def test_real_manifests_share_release_version(self):
        # Step13 (Q7): the real manifests, not the valid() fixture, carry 0.1.0.
        inv=policy.inventory(ROOT);workspace=tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']
        internal={k:v for k,v in workspace['dependencies'].items() if 'path' in v}
        self.assertEqual(inv['version'],'0.1.0');self.assertEqual(workspace['package']['version'],'0.1.0')
        self.assertEqual(sorted(internal),sorted(policy.PUBLIC));self.assertEqual({v['version'] for v in internal.values()},{'0.1.0'})
        self.assertEqual(len(inv['packages']),11);self.assertEqual({r['version'] for r in inv['packages'].values()},{'0.1.0'})
        self.assertEqual({v for r in inv['packages'].values() for v in r['dependencies'].values()},{'0.1.0'})
        self.assertEqual(inv['npm']['version'],'0.1.0');self.assertEqual(inv['npm']['name'],'@aletheia-works/paludarium-wasm')
    def test_single_version_drift_rejected(self):
        drifts={'workspace dependency':('Cargo.toml','paludarium-mmu = { path = "crates/paludarium-mmu", version = "0.1.0" }','paludarium-mmu = { path = "crates/paludarium-mmu", version = "0.1.1" }'),
                'npm package':('packages/paludarium-wasm/package.json','"version":"0.1.0"','"version":"0.1.1"'),
                'crate package':('crates/paludarium-vfs/Cargo.toml','\nversion.workspace = true','\nversion = "0.1.1"')}
        for label,(path,old,new) in drifts.items():
            with self.subTest(label),tempfile.TemporaryDirectory(dir=ROOT/'target/u15') as directory:
                root=Path(directory);members=tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['members']
                for name in ['Cargo.toml','packages/paludarium-wasm/package.json']+[m+'/Cargo.toml' for m in members]:
                    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
                text=(root/path).read_text();self.assertEqual(text.count(old),1,label);(root/path).write_text(text.replace(old,new))
                with self.assertRaisesRegex(ValueError,'version'):policy.inventory(root)

if __name__=='__main__':unittest.main()
