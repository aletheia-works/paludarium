import copy,io,json,re,sys,tempfile,unittest,os,urllib.error
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts/release'))
import check,policy

CANARY={'U15_OIDC_CRATES_IO_TOKEN':'canary-oidc-0001','U15_FIRST_CRATES_IO_TOKEN':'canary-crates-0002','U15_FIRST_NPM_TOKEN':'canary-npm-0003'}
# (canary values are test strings, never real tokens)

# Declared owners as the release environment variables give them (fixture logins, not real accounts).
OWNERS={'crates':['github:aletheia-works:owners','paludarium-owner'],'npm':['paludarium-owner']}
OWNER_ENV={'U15_CRATES_IO_OWNERS':'paludarium-owner, github:aletheia-works:owners','U15_NPM_MAINTAINERS':'paludarium-owner'}

class Registry:
    """In-memory crates.io/npm presence, version digests and owners; never reaches the network.
    `versions` maps a present name to the digest of its 0.1.0 (None: an unreadable body);
    `yanked` names versions that crates.io marks yanked; `owners` maps a present name to its
    owner logins (default: the declared OWNERS; None: an unreadable owners body)."""
    def __init__(self,present=(),status=None,unreachable=False,versions=None,yanked=(),owners=None):
        self.present,self.status,self.unreachable,self.requests=set(present),status,unreachable,[]
        self.versions=dict(versions or {});self.yanked=set(yanked);self.owners=dict(owners or {})
    def owners_of(self,name):
        return self.owners.get(name,OWNERS['npm' if name==check.NPM_NAME else 'crates'])
    def __call__(self,request,timeout):
        self.requests.append(request);url=request.full_url
        if self.unreachable:raise urllib.error.URLError('down')
        if self.status:raise urllib.error.HTTPError(url,self.status,'unavailable',{},None)
        if url.startswith(check.NPM_PACKAGE_URL):name,rest=check.NPM_NAME,url[len(check.NPM_PACKAGE_URL)+1:]
        else:name,_,rest=url[len(check.CRATES_API):].partition('/')
        if name not in self.present:raise urllib.error.HTTPError(url,404,'absent',{},None)
        owners=self.owners_of(name)
        if not rest:
            if name==check.NPM_NAME and owners is not None:return io.BytesIO(json.dumps(dict(maintainers=[dict(name=n,email=n+'@example.invalid') for n in owners])).encode())
            return io.BytesIO(b'{}')
        if rest=='owners':
            return io.BytesIO(b'{}' if owners is None else json.dumps(dict(users=[dict(id=i,login=n,kind='team' if n.startswith('github:') else 'user') for i,n in enumerate(owners)])).encode())
        if name not in self.versions:raise urllib.error.HTTPError(url,404,'absent',{},None)
        digest=self.versions[name]
        if digest is None:return io.BytesIO(b'{}')
        body=dict(version=rest,dist=dict(integrity=digest)) if name==check.NPM_NAME else dict(version=dict(num=rest,checksum=digest,yanked=name in self.yanked))
        return io.BytesIO(json.dumps(body).encode())

def approved_set(order):
    """Approved digests as approved_digests() returns them (fixture values, not real artifacts)."""
    digests={name:'%064x'%i for i,name in enumerate(order,1)}
    digests[check.NPM_NAME]='sha512-'+'A'*86+'=='
    return digests

class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'target/u15');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def run_child(self,code,timeout=5):
        return check.run_command([sys.executable,'-B','-c',code],self.root,self.root/'receipt',timeout)
    def test_success(self):
        r=self.run_child('print("ok")');check.require_success(r)
        self.assertEqual((self.root/'receipt/stdout.bin').read_bytes(),b'ok\n')
    def test_failure(self):
        r=self.run_child('raise SystemExit(7)')
        with self.assertRaises(ValueError):check.require_success(r)
        self.assertEqual(r['exit'],7)
    def test_timeout(self):
        r=self.run_child('import time;print("partial",flush=True);time.sleep(10)',.05)
        self.assertTrue(r['timeout']);self.assertTrue(r['reaped']);self.assertTrue(r['cleanup'])
        with self.assertRaises(ValueError):check.require_success(r)
    def test_missing_tool(self):
        r=check.run_command([str(self.root/'absent')],self.root,self.root/'receipt')
        self.assertIsNotNone(r['error'])
    def test_shim_refused(self):
        with self.assertRaises(ValueError):check.run_command(['/example/shims/python'],self.root,self.root/'receipt')
    def test_incomplete_receipt(self):
        with self.assertRaises(ValueError):check.require_success(dict(exit=0,timeout=False,error=None,reaped=False))
    def test_source_changed(self):
        (self.root/'source').write_bytes(b'before')
        with self.assertRaises(ValueError):check.checked_command([sys.executable,'-c','open("source","w").write("changed")'],self.root,self.root/'receipt',[Path('source')])
    def test_source_unchanged(self):
        (self.root/'source').write_bytes(b'before')
        self.assertEqual(check.checked_command([sys.executable,'-c','print("ok")'],self.root,self.root/'receipt',[Path('source')])['exit'],0)
    def test_unpublished(self):self.assertEqual(check.registry_state(404,{},'1','x')['state'],'UNPUBLISHED')
    def test_published(self):self.assertFalse(check.registry_state(200,dict(version='1',digest='x'),'1','x')['upload_allowed'])
    def test_query_unknown(self):
        with self.assertRaises(ValueError):check.registry_state(503,{},'1','x')
    def test_digest_mismatch(self):
        with self.assertRaises(ValueError):check.registry_state(200,dict(version='1',digest='other'),'1','x')
    def test_version_mismatch(self):
        with self.assertRaises(ValueError):check.registry_state(200,dict(version='2',digest='x'),'1','x')
    def test_bad_timeout(self):
        with self.assertRaises(ValueError):self.run_child('pass',0)
    def test_secret_environment_not_dumped(self):
        env=dict(os.environ,SECRET_CANARY='never-log-this',RUSTFLAGS='')
        receipt=check.run_command([sys.executable,'-c','pass'],self.root,self.root/'receipt',env=env)
        self.assertEqual(receipt['tool_environment']['RUSTFLAGS'],'')
        self.assertNotIn('never-log-this',(self.root/'receipt/receipt.json').read_text())
    # Step14b (Q2): a decided version is no longer reported as outstanding.
    def test_validate_outstanding_follows_version(self):
        decided=check.validate(ROOT)
        self.assertEqual(decided['version'],'0.1.0');self.assertNotIn('release version',decided['outstanding'])
        self.assertIn('initial registry ownership/publishers',decided['outstanding'])
        undecided=copy.deepcopy(policy.inventory(ROOT));undecided['version']='0.0.0'
        with patch.object(policy,'inventory',return_value=undecided):
            self.assertEqual(check.validate(ROOT)['outstanding'][0],'release version')
    # Step14b (Q4): live absence check for the one-time first publication.
    def absence(self,registry):
        with patch.object(check.urllib.request,'urlopen',side_effect=registry):
            return check.registries_absent(policy.inventory(ROOT)['order'])
    def test_registries_absent(self):
        registry=Registry();result=self.absence(registry)
        self.assertTrue(result['absent']);self.assertEqual(len(result['checked']),12);self.assertEqual(len(registry.requests),12)
        self.assertTrue(all(r.get_method()=='GET' and r.get_header('User-agent')==check.REGISTRY_USER_AGENT for r in registry.requests))
    def test_registry_name_present(self):
        for name in ('paludarium-types','@aletheia-works/paludarium-wasm'):
            with self.subTest(name):
                result=self.absence(Registry(present=[name]))
                self.assertFalse(result['absent']);self.assertEqual(result['present'],[name])
                # Step24 (review 04, finding 6b): without approved digests a present name is never an empty `mismatched`.
                self.assertFalse(result['resume']);self.assertEqual([m['name'] for m in result['mismatched']],[name])
                self.assertIn('approved digests not supplied',result['mismatched'][0]['reason'])
    def test_registry_presence_unknown(self):
        with self.assertRaisesRegex(ValueError,'503'):self.absence(Registry(status=503))
        with self.assertRaisesRegex(ValueError,'unreachable'):self.absence(Registry(unreachable=True))
    def test_oidc_environments(self):
        env=dict(PATH='/bin',U15_OIDC_CRATES_IO_TOKEN=CANARY['U15_OIDC_CRATES_IO_TOKEN'],CARGO_REGISTRY_TOKEN='stale')
        dry,cargo,npm=check.publication_environments('oidc',env)
        self.assertEqual(cargo['CARGO_REGISTRY_TOKEN'],CANARY['U15_OIDC_CRATES_IO_TOKEN'])
        for e in (dry,npm):self.assertFalse(set(e)&{'CARGO_REGISTRY_TOKEN','U15_OIDC_CRATES_IO_TOKEN'})
        with self.assertRaisesRegex(ValueError,'still configured'):
            check.publication_environments('oidc',dict(env,U15_FIRST_NPM_TOKEN=CANARY['U15_FIRST_NPM_TOKEN']))
        with self.assertRaisesRegex(ValueError,'OIDC token absent'):check.publication_environments('oidc',dict(PATH='/bin'))
    def test_first_publication_environments(self):
        env=dict(PATH='/bin',U15_FIRST_CRATES_IO_TOKEN=CANARY['U15_FIRST_CRATES_IO_TOKEN'],U15_FIRST_NPM_TOKEN=CANARY['U15_FIRST_NPM_TOKEN'])
        dry,cargo,npm=check.publication_environments('first-publication-token',env)
        self.assertEqual(cargo['CARGO_REGISTRY_TOKEN'],CANARY['U15_FIRST_CRATES_IO_TOKEN']);self.assertEqual(npm['NODE_AUTH_TOKEN'],CANARY['U15_FIRST_NPM_TOKEN'])
        self.assertFalse(set(CANARY.values())&set(dry.values()));self.assertNotIn(CANARY['U15_FIRST_NPM_TOKEN'],cargo.values())
        self.assertNotIn(CANARY['U15_FIRST_CRATES_IO_TOKEN'],npm.values())
        with self.assertRaisesRegex(ValueError,'tokens absent'):check.publication_environments('first-publication-token',dict(env,U15_FIRST_NPM_TOKEN=''))
        with self.assertRaisesRegex(ValueError,'OIDC token present'):check.publication_environments('first-publication-token',dict(env,U15_OIDC_CRATES_IO_TOKEN='x'))
        with self.assertRaisesRegex(ValueError,'unknown'):check.publication_environments('long-lived',env)
    def test_upload_tokens_not_in_receipt(self):
        env=dict(os.environ,CARGO_REGISTRY_TOKEN=CANARY['U15_FIRST_CRATES_IO_TOKEN'],NODE_AUTH_TOKEN=CANARY['U15_FIRST_NPM_TOKEN'])
        check.run_command([sys.executable,'-c','pass'],self.root,self.root/'receipt',env=env)
        text=(self.root/'receipt/receipt.json').read_text()
        self.assertFalse([v for v in CANARY.values() if v in text])
    def test_release_workflow_secret_scope(self):
        text=(ROOT/'.github/workflows/publish.yml').read_text();publish=text.split('\n  publish:\n',1)[1]
        self.assertEqual(sorted(re.findall(r'secrets\.(\w+)',text)),['U15_FIRST_CRATES_IO_TOKEN','U15_FIRST_NPM_TOKEN'])
        self.assertEqual(len(re.findall(r'secrets\.',publish)),2);self.assertIn('    environment: release\n',publish)
        self.assertFalse([l for l in text.splitlines() if 'secrets.' in l and not re.fullmatch(r'\s+U15_FIRST_\w+: \$\{\{ secrets\.U15_FIRST_\w+ \}\}',l)])
        oidc=publish.split('id: crates\n',1)[1].split('\n',1)[0]
        self.assertEqual(oidc.strip(),"if: steps.authorize.outputs.authentication == 'oidc'")
        for name in ('publish.yml','u15-acceptance.yml','release-check.yml'):
            self.assertNotRegex((ROOT/'.github/workflows'/name).read_text(),r'(?i)echo[^\n]*(token|secret)')
    # Step17 (R-16): resuming a stopped first publication.
    def presence(self,registry,approved,owners=OWNERS):
        order=policy.inventory(ROOT)['order']
        with patch.object(check.urllib.request,'urlopen',side_effect=registry):
            return check.registries_absent(order,'0.1.0',approved,owners)
    def test_resume_when_present_versions_match(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order);done=order[:3]+[check.NPM_NAME]
        registry=Registry(present=done,versions={n:approved[n] for n in done});result=self.presence(registry,approved)
        self.assertEqual((result['absent'],result['resume'],result['mismatched']),(False,True,[]))
        # 12 presence queries, then for each of the 4 present names its version and its owners
        self.assertEqual(result['matching'],sorted(done));self.assertEqual(len(registry.requests),12+4*2)
        versions=[r.full_url for r in registry.requests[12:]]
        self.assertIn(check.CRATES_API+order[0]+'/0.1.0',versions);self.assertIn(check.NPM_PACKAGE_URL+'/0.1.0',versions)
        self.assertIn(check.CRATES_API+order[0]+'/owners',versions);self.assertIn(check.NPM_PACKAGE_URL,versions)
    # Step24 (review 04, finding 3): owners and maintainers of present names must be the declared ones.
    def test_resume_refused_when_owners_differ(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order);done=[order[0],order[1],check.NPM_NAME]
        versions={n:approved[n] for n in done}
        for owners,who in (({order[1]:['someone-else']},order[1]),({order[0]:OWNERS['crates']+['extra-owner']},order[0]),
                           ({check.NPM_NAME:['someone-else']},check.NPM_NAME),({check.NPM_NAME:[]},check.NPM_NAME),({order[0]:None},order[0])):
            with self.subTest(who=who,owners=owners):
                result=self.presence(Registry(present=done,versions=versions,owners=owners),approved)
                self.assertFalse(result['resume']);self.assertEqual([m['name'] for m in result['mismatched']],[who])
                self.assertRegex(result['mismatched'][0]['reason'],'differ from the declared owners|owners unreadable')
    def test_resume_refused_without_declared_owners(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order)
        result=self.presence(Registry(present=[order[0]],versions={order[0]:approved[order[0]]}),approved,None)
        self.assertFalse(result['resume']);self.assertIn('expected owners not declared',result['mismatched'][0]['reason'])
    def test_expected_owners_from_release_environment(self):
        self.assertEqual(check.expected_owners(OWNER_ENV),OWNERS)
        for env in ({},dict(OWNER_ENV,U15_NPM_MAINTAINERS=''),dict(OWNER_ENV,U15_CRATES_IO_OWNERS=' , '),{'U15_CRATES_IO_OWNERS':'a'}):
            self.assertIsNone(check.expected_owners(env))
    # Step24 (review 04, finding 4): a yanked crates.io version never matches.
    def test_resume_refused_when_version_yanked(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order);done=order[:2]
        result=self.presence(Registry(present=done,versions={n:approved[n] for n in done},yanked=[order[1]]),approved)
        self.assertFalse(result['resume']);self.assertEqual(result['matching'],[order[0]])
        self.assertEqual(result['mismatched'],[dict(name=order[1],reason='published 0.1.0 is yanked')])
    def test_published_digest_needs_an_explicit_unyanked_flag(self):
        def body(row):return patch.object(check,'registry_version',return_value=dict(version=row))
        with body(dict(num='0.1.0',checksum='a'*64,yanked=False)):self.assertEqual(check.published_digest('paludarium-types','0.1.0'),('present','a'*64))
        with body(dict(num='0.1.0',checksum='a'*64,yanked=True)):self.assertEqual(check.published_digest('paludarium-types','0.1.0'),('yanked',None))
        with body(dict(num='0.1.0',checksum='a'*64)):self.assertEqual(check.published_digest('paludarium-types','0.1.0'),('unreadable',None))
        with body(dict(num='0.1.0',checksum='a'*64,yanked='false')):self.assertEqual(check.published_digest('paludarium-types','0.1.0'),('unreadable',None))
    def test_registry_state_refuses_yanked(self):
        with self.assertRaisesRegex(ValueError,'yanked'):check.registry_state(200,dict(version='1',digest='x',yanked=True),'1','x')
        self.assertEqual(check.registry_state(200,dict(version='1',digest='x',yanked=False),'1','x')['state'],'PUBLISHED_MATCH')
    def test_resume_refused_when_one_version_differs(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order);done=order[:3]
        versions={n:approved[n] for n in done};versions[order[1]]='f'*64
        result=self.presence(Registry(present=done,versions=versions),approved)
        self.assertFalse(result['resume']);self.assertEqual([m['name'] for m in result['mismatched']],[order[1]])
        self.assertEqual(sorted(result['matching']),sorted([order[0],order[2]]))
    def test_resume_refused_for_npm_integrity_difference(self):
        approved=approved_set(policy.inventory(ROOT)['order'])
        result=self.presence(Registry(present=[check.NPM_NAME],versions={check.NPM_NAME:'sha512-other'}),approved)
        self.assertFalse(result['resume']);self.assertIn('differs',result['mismatched'][0]['reason'])
    def test_resume_refused_when_version_absent_or_unreadable(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order)
        result=self.presence(Registry(present=[order[0],order[1]],versions={order[1]:None}),approved)
        reasons={m['name']:m['reason'] for m in result['mismatched']}
        self.assertFalse(result['resume']);self.assertIn('without the approved version',reasons[order[0]]);self.assertIn('unreadable',reasons[order[1]])
    def test_resume_refused_without_approved_digest(self):
        order=policy.inventory(ROOT)['order'];approved=approved_set(order);del approved[order[0]]
        result=self.presence(Registry(present=[order[0]],versions={order[0]:'%064x'%1}),approved)
        self.assertFalse(result['resume'])
    def test_approved_digests_loaded_only_when_present(self):
        def loader():raise AssertionError('loaded although nothing is present')
        result=self.presence(Registry(),loader);self.assertTrue(result['absent']);self.assertFalse(result['resume'])
        with self.assertRaisesRegex(ValueError,'artifact absent'):
            self.presence(Registry(present=['paludarium-types']),lambda:check.approved_digests(self.root,'a'*40))
    def test_resume_version_query_unknown_stops(self):
        order=policy.inventory(ROOT)['order']
        def registry(request,timeout):
            if request.full_url.endswith('/0.1.0'):raise urllib.error.HTTPError(request.full_url,503,'unavailable',{},None)
            return Registry(present=[order[0]])(request,timeout)
        with self.assertRaisesRegex(ValueError,'version state unknown'):self.presence(registry,approved_set(order))
    # Step17 (R-17): allow-listed child environments.
    def job_environment(self):
        return dict(PATH='/bin',HOME='/home/runner',CI='true',GITHUB_ACTIONS='true',GH_TOKEN='canary-gh-0004',GITHUB_TOKEN='canary-gh-0005',
            ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.invalid',ACTIONS_ID_TOKEN_REQUEST_TOKEN='canary-oidc-request-0006',
            GITHUB_REPOSITORY=policy.REPOSITORY,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_REF=policy.REPOSITORY+'/.github/workflows/publish.yml@refs/tags/v0.1.0',
            RUNNER_ENVIRONMENT='github-hosted',NPM_CONFIG_USERCONFIG='/tmp/.npmrc',RUSTC='/toolchain/rustc',UNRELATED_SECRET='canary-other-0007',
            PALUDARIUM_RELEASE_NPM='/npm-cli.js')
    def test_cargo_children_get_no_github_or_oidc_request_variables(self):
        for mode,extra in (('oidc',dict(U15_OIDC_CRATES_IO_TOKEN=CANARY['U15_OIDC_CRATES_IO_TOKEN'])),
                           ('first-publication-token',{k:CANARY[k] for k in check.FIRST_TOKEN_NAMES})):
            with self.subTest(mode):
                dry,cargo,_=check.publication_environments(mode,dict(self.job_environment(),**extra))
                for env in (dry,cargo):
                    self.assertFalse([k for k in env if k.startswith(('GH_','GITHUB_','ACTIONS_'))]);self.assertNotIn('UNRELATED_SECRET',env)
                    self.assertLessEqual(set(env),set(check.CARGO_ENVIRONMENT)|{'CARGO_REGISTRY_TOKEN'})
                self.assertEqual((dry['PATH'],dry['RUSTC']),('/bin','/toolchain/rustc'));self.assertNotIn('CARGO_REGISTRY_TOKEN',dry)
    def test_npm_child_gets_only_provenance_variables(self):
        for mode,extra,token in (('oidc',dict(U15_OIDC_CRATES_IO_TOKEN=CANARY['U15_OIDC_CRATES_IO_TOKEN'],NODE_AUTH_TOKEN='XXXXX-XXXXX-XXXXX-XXXXX'),'XXXXX-XXXXX-XXXXX-XXXXX'),
                           ('first-publication-token',{k:CANARY[k] for k in check.FIRST_TOKEN_NAMES},CANARY['U15_FIRST_NPM_TOKEN'])):
            with self.subTest(mode):
                npm=check.publication_environments(mode,dict(self.job_environment(),**extra))[2]
                self.assertLessEqual(set(npm),set(check.NPM_ENVIRONMENT))
                for name in ('ACTIONS_ID_TOKEN_REQUEST_URL','ACTIONS_ID_TOKEN_REQUEST_TOKEN','GITHUB_WORKFLOW_REF','GITHUB_SHA','RUNNER_ENVIRONMENT','NPM_CONFIG_USERCONFIG','CI'):
                    self.assertIn(name,npm)
                for name in ('GH_TOKEN','GITHUB_TOKEN','UNRELATED_SECRET','RUSTC','PALUDARIUM_RELEASE_NPM','CARGO_REGISTRY_TOKEN','U15_OIDC_CRATES_IO_TOKEN','U15_FIRST_CRATES_IO_TOKEN','U15_FIRST_NPM_TOKEN'):
                    self.assertNotIn(name,npm)
                self.assertEqual(npm['NODE_AUTH_TOKEN'],token)

if __name__=='__main__':unittest.main()
