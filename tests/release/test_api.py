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
    # Trusted Publishing only: authorization reads no declaration, queries no registry and sets no mode.
    def test_authorize_needs_no_declaration_or_registry(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',side_effect=self.github),patch.object(policy,'inventory',return_value=self.inv),\
             patch.object(check,'registry_presence',side_effect=AssertionError('not consulted')),patch.object(check.urllib.request,'urlopen',side_effect=AssertionError('no network')):
            result=check.authorize(ROOT,self.path)
        self.assertTrue(result['eligible']);self.assertNotIn('authentication',result)
    def test_authorize_writes_no_step_output(self):
        output=Path(self.temp.name)/'github-output'
        with patch.dict(os.environ,dict(self.env,GITHUB_OUTPUT=str(output))),patch.object(check,'authorize',return_value=dict(eligible=True,head='a'*40)),\
             patch.object(sys,'argv',['check.py','--mode','authorize','--evidence',str(self.path)]),patch('builtins.print') as printed:
            check.main()
        self.assertFalse(output.exists());printed.assert_called_once_with(json.dumps(dict(eligible=True,head='a'*40)))
    def test_acceptance_pagination_refused(self):
        with patch.dict(os.environ,self.env),patch.object(check,'github',return_value=dict(total_count=101,workflow_runs=[])):
            with self.assertRaises(ValueError):check.fetch_acceptance(ROOT)

if __name__=='__main__':unittest.main()
