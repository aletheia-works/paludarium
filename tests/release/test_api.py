"""Official API adapter/control tests; no real approval, OIDC or upload."""
import copy,io,json,os,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from test_policy import valid,ROOT
import check,package,policy

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.s,self.inv=valid();self.env=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=policy.REPOSITORY,GITHUB_REF_NAME='v0.1.0',GITHUB_REF_TYPE='tag',GITHUB_SHA='a'*40,GITHUB_RUN_ID='101',GH_TOKEN='not-a-real-token')
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'target/u15');self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'evidence.json';self.path.write_text(json.dumps(self.s))
    def github(self,route):
        if route.startswith('commits/'):return self.s['commit']
        if route.startswith('compare/'):return self.s['main_compare']
        if route=='environments/release':return self.s['environment']
        return dict(head_sha='a'*40,repository=dict(full_name=policy.REPOSITORY),status='completed',conclusion='success')
    def test_official_authorization_adapter(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=self.github),patch.object(policy,'inventory',return_value=self.inv):
            self.assertTrue(check.authorize(ROOT,self.path)['eligible'])
    def test_official_head_mismatch(self):
        def api(route):
            d=self.github(route)
            if route.startswith('actions/runs/') and not route.endswith('/approvals'):d['head_sha']='c'*40
            return d
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=api),patch.object(policy,'inventory',return_value=self.inv):
            with self.assertRaises(ValueError):check.authorize(ROOT,self.path)
    def test_no_environment_approval_needed(self):
        def api(route):
            self.assertFalse(route.endswith('/approvals'));return self.github(route)
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=api),patch.object(policy,'inventory',return_value=self.inv):
            self.assertTrue(check.authorize(ROOT,self.path)['eligible'])
    def test_missing_acceptance_file(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=self.github),patch.object(policy,'inventory',return_value=self.inv):
            with self.assertRaises(ValueError):check.authorize(ROOT,None)
    def test_fork_preflight_rejected(self):
        with patch.dict(os.environ,dict(self.env,GITHUB_REPOSITORY='attacker/fork')),patch.object(policy,'inventory',return_value=self.inv):
            with self.assertRaises(ValueError):check.preflight(ROOT)
    def test_official_environment_missing(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=lambda r:{} if r=='environments/release' else self.github(r)),patch.object(policy,'inventory',return_value=self.inv):
            with self.assertRaises(ValueError):check.preflight(ROOT)
    def test_network_adapter(self):
        with patch.dict(os.environ,self.env),patch.object(check.urllib.request,'urlopen',return_value=io.BytesIO(b'{"id":1}')):
            self.assertEqual(check.github('actions/runs/1')['id'],1)
    def test_network_failure_unknown(self):
        error=check.urllib.error.HTTPError('https://example.invalid',503,'unavailable',{},None)
        with patch.dict(os.environ,self.env),patch.object(check.urllib.request,'urlopen',side_effect=error):
            with self.assertRaisesRegex(ValueError,'503'):check.github('actions/runs/1')
    def test_acceptance_fetch_adapter(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as a:a.writestr('release-evidence.json',json.dumps(dict(head='a'*40)))
        raw=buf.getvalue();artifact=dict(name='u15-acceptance',expired=False,workflow_run=dict(head_sha='a'*40),digest='sha256:'+package.sha(raw),archive_download_url='https://example.invalid/archive')
        def api(route):
            if route.startswith('actions/runs?'):return dict(total_count=1,workflow_runs=[dict(id=1,head_sha='a'*40,repository=dict(full_name=policy.REPOSITORY))])
            return dict(total_count=1,artifacts=[artifact])
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=api),patch.object(check.urllib.request,'urlopen',return_value=io.BytesIO(raw)):
            self.assertEqual(check.fetch_acceptance(ROOT)['head'],'a'*40)
    def test_acceptance_fetch_follows_redirect_without_token(self):
        # The artifact API redirects to pre-signed storage, which refuses an Authorization header (401).
        import http.server,threading
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as a:a.writestr('release-evidence.json',json.dumps(dict(head='a'*40)))
        raw=buf.getvalue();seen={}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.path=='/api/zip':
                    seen['api']=self.headers.get('Authorization');self.send_response(302)
                    self.send_header('Location','http://127.0.0.1:%d/blob'%self.server.server_port);self.end_headers()
                elif self.headers.get('Authorization'):
                    seen['blob']=self.headers.get('Authorization');self.send_response(401);self.end_headers()
                else:
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        server=http.server.HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            artifact=dict(name='u15-acceptance',expired=False,workflow_run=dict(head_sha='a'*40),digest='sha256:'+package.sha(raw),
                          archive_download_url='http://127.0.0.1:%d/api/zip'%server.server_port)
            def api(route):
                if route.startswith('actions/runs?'):return dict(total_count=1,workflow_runs=[dict(id=1,head_sha='a'*40,repository=dict(full_name=policy.REPOSITORY))])
                return dict(total_count=1,artifacts=[artifact])
            with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=api):
                self.assertEqual(check.fetch_acceptance(ROOT)['head'],'a'*40)
        finally:
            server.shutdown();server.server_close()
        self.assertTrue(seen['api'].startswith('Bearer '));self.assertNotIn('blob',seen)
    def test_acceptance_missing(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',return_value=dict(total_count=0,workflow_runs=[])):
            with self.assertRaises(ValueError):check.fetch_acceptance(ROOT)
    # Step14b (Q4): the first-publication declaration needs a live absence check.
    def authorize_first(self,registry,approved=None,owner_env=None,**fields):
        self.s.update(dict(trusted_publishers_registered=False,first_publication=True),**fields);self.path.write_text(json.dumps(self.s))
        from test_check import approved_set,OWNER_ENV
        self.approved=approved or approved_set(self.inv['order']);self.loaded=[]
        def digests(root,head):self.loaded.append(head);return self.approved
        env=dict(self.env,**(OWNER_ENV if owner_env is None else owner_env))
        with patch.dict(os.environ,env),patch.object(check,'github',side_effect=self.github),patch.object(policy,'inventory',return_value=self.inv),\
             patch.object(check.urllib.request,'urlopen',side_effect=registry),patch.object(check,'approved_digests',side_effect=digests):
            return check.authorize(ROOT,self.path)
    def test_first_publication_authorized_when_absent(self):
        from test_check import Registry
        registry=Registry();self.assertEqual(self.authorize_first(registry)['authentication'],'first-publication-token')
        self.assertEqual(len(registry.requests),12)
    def test_first_publication_refused_when_present(self):
        from test_check import Registry
        with self.assertRaisesRegex(ValueError,'trusted publishers unregistered'):self.authorize_first(Registry(present=['paludarium-cpu']))
    def test_document_cannot_assert_absence(self):
        from test_check import Registry
        with self.assertRaisesRegex(ValueError,'trusted publishers unregistered'):
            self.authorize_first(Registry(present=['@aletheia-works/paludarium-wasm']),registries_absent=True)
    # Step17 (R-16): a stopped first publication continues only over matching present versions.
    def test_first_publication_resumes_when_present_versions_match(self):
        from test_check import Registry,approved_set
        approved=approved_set(self.inv['order']);done=self.inv['order'][:4]
        registry=Registry(present=done,versions={n:approved[n] for n in done})
        self.assertEqual(self.authorize_first(registry,approved)['authentication'],'first-publication-token')
        self.assertEqual(self.loaded,['a'*40]);self.assertEqual(len(registry.requests),12+4*2)
    # Step24 (review 04, finding 3): the expected owners come from the release environment variables.
    def test_first_publication_resume_refused_on_other_owner_or_undeclared_owners(self):
        from test_check import Registry,approved_set
        approved=approved_set(self.inv['order']);done=self.inv['order'][:2]
        versions={n:approved[n] for n in done}
        with self.assertRaisesRegex(ValueError,'resume refused: '+done[1]+': owners someone-else differ'):
            self.authorize_first(Registry(present=done,versions=versions,owners={done[1]:['someone-else']}),approved)
        with self.assertRaisesRegex(ValueError,'expected owners not declared'):
            self.authorize_first(Registry(present=done,versions=versions),approved,owner_env={'U15_CRATES_IO_OWNERS':'','U15_NPM_MAINTAINERS':''})
    def test_first_publication_resume_refused_on_yanked_version(self):
        from test_check import Registry,approved_set
        approved=approved_set(self.inv['order']);done=self.inv['order'][:1]
        with self.assertRaisesRegex(ValueError,'is yanked'):
            self.authorize_first(Registry(present=done,versions={n:approved[n] for n in done},yanked=done),approved)
    def test_first_publication_resume_refused_on_one_difference(self):
        from test_check import Registry,approved_set
        approved=approved_set(self.inv['order']);done=self.inv['order'][:4]+['@aletheia-works/paludarium-wasm']
        versions={n:approved[n] for n in done};versions['@aletheia-works/paludarium-wasm']='sha512-other'
        with self.assertRaisesRegex(ValueError,'resume refused: @aletheia-works/paludarium-wasm'):self.authorize_first(Registry(present=done,versions=versions),approved)
    def test_document_cannot_assert_resume(self):
        from test_check import Registry
        with self.assertRaisesRegex(ValueError,'resume refused'):
            self.authorize_first(Registry(present=['paludarium-types'],versions={'paludarium-types':'0'*64}),registry_resume_verified=True)
    def test_resume_without_first_publication_declaration_refused(self):
        from test_check import Registry,approved_set
        approved=approved_set(self.inv['order']);done=self.inv['order'][:2]
        with self.assertRaisesRegex(ValueError,'trusted publishers unregistered'):
            self.authorize_first(Registry(present=done,versions={n:approved[n] for n in done}),approved,first_publication=False)
        self.assertEqual(self.loaded,[])
    def test_registered_publishers_skip_registry_check(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=self.github),patch.object(policy,'inventory',return_value=self.inv),\
             patch.object(check,'registries_absent',side_effect=AssertionError('not consulted')):
            self.assertEqual(check.authorize(ROOT,self.path)['authentication'],'oidc')
    def test_authorize_writes_only_mode_to_step_output(self):
        output=Path(self.temp.name)/'github-output'
        with patch.dict(os.environ,dict(self.env,GITHUB_OUTPUT=str(output))),patch.object(check,'authorize',return_value=dict(authentication='oidc',head='a'*40)),\
             patch.object(sys,'argv',['check.py','--mode','authorize','--evidence',str(self.path)]),patch('builtins.print'):
            check.main()
        self.assertEqual(output.read_text(),'authentication=oidc\n')
    def test_acceptance_pagination_refused(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',return_value=dict(total_count=101,workflow_runs=[])):
            with self.assertRaises(ValueError):check.fetch_acceptance(ROOT)

if __name__=='__main__':unittest.main()
