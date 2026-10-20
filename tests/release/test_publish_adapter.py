"""Real archive fixtures with mocked network/upload adapters, never a publication."""
import base64,hashlib,io,json,os,shutil,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from test_package import tar
from test_policy import ROOT
from test_check import CANARY
import check,package,policy

class PublishAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'target/u15');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.head='a'*40
        sourcefiles={}
        sourcefiles['Cargo.toml']=(ROOT/'Cargo.toml').read_bytes().replace(b'0.0.0',b'0.1.0')
        sourcefiles['rust-toolchain.toml']=(ROOT/'rust-toolchain.toml').read_bytes()
        for member in __import__('tomllib').loads(sourcefiles['Cargo.toml'].decode())['workspace']['members']:
            sourcefiles[member+'/Cargo.toml']=(ROOT/member/'Cargo.toml').read_bytes()
        sourcefiles['packages/paludarium-wasm/package.json']=(ROOT/'packages/paludarium-wasm/package.json').read_bytes().replace(b'0.0.0',b'0.1.0')
        for n,b in sourcefiles.items():
            p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        self.inv=policy.inventory(self.root);self.out=self.root/'target/u15';self.art=self.out/'package-test';self.art.mkdir(parents=True)
        self.crates=[]
        for name in self.inv['order']:
            dep='\n'.join('[dependencies.'+d+']\nversion="'+v+'"' for d,v in self.inv['packages'][name]['dependencies'].items())
            m='[package]\nname="'+name+'"\nversion="0.1.0"\nlicense="Apache-2.0"\n'+dep
            p=self.art/'source/target/package'/(name+'-0.1.0.crate');p.parent.mkdir(parents=True,exist_ok=True)
            tar(p,{'Cargo.toml':m.encode(),'LICENSE':b'Apache','README.md':b'usage'},name+'-0.1.0');self.crates.append(p)
        files={n:b'export {};' for n in package.REQUIRED_JS}
        files.update({'package.json':b'{"name":"@aletheia-works/paludarium-wasm","version":"0.1.0"}',
          'paludarium.wasm':b'\0asm\x01\0\0\0','index.d.ts':b'export {};','LICENSE':b'Apache','README.md':b'usage'})
        self.npm=self.art/'wasm.tgz';tar(self.npm,files)
        with zipfile.ZipFile(self.art/'source-snapshot.zip','x') as z:
            for n,b in sourcefiles.items():z.writestr(n,b)
        sourcehash=package.sha(json.dumps({n:package.sha(b) for n,b in sourcefiles.items()},sort_keys=True).encode())
        expected=dict(version='0.1.0',head=self.head,source_sha256=sourcehash,tar_sha256=package.sha(self.npm.read_bytes()),wasm_sha256=package.sha(files['paludarium.wasm']),source_files={})
        self.result=dict(passed=True,head=self.head,local_snapshot=False,source_sha256=sourcehash,
            crates=package.inspect_crates(self.crates,self.inv),npm=package.inspect_npm(self.npm,expected))
        (self.out/'package-result.json').write_text(json.dumps(self.result));self.uploaded=set()
        self.env=dict(PALUDARIUM_TEST_NODE=sys.executable,PALUDARIUM_RELEASE_NPM=__file__,U15_OIDC_CRATES_IO_TOKEN=CANARY['U15_OIDC_CRATES_IO_TOKEN'])
        self.envs=[];self.yanked=set();self.dry_dir='target/package/tmp-crate'
    def request(self,url,timeout):
        if 'crates.io/' in url:
            name=url.split('/')[-2]
            if name not in self.uploaded:raise check.urllib.error.HTTPError(url,404,'absent',{},None)
            return io.BytesIO(json.dumps(dict(version=dict(num='0.1.0',checksum=self.result['crates'][name]['sha256'],yanked=name in self.yanked))).encode())
        if 'npm' not in self.uploaded:raise check.urllib.error.HTTPError(url,404,'absent',{},None)
        digest='sha512-'+base64.b64encode(hashlib.sha512(self.npm.read_bytes()).digest()).decode()
        return io.BytesIO(json.dumps(dict(version='0.1.0',dist=dict(integrity=digest))).encode())
    def command(self,argv,cwd,output,*args,**kwargs):
        self.envs.append((Path(output).name,args[-1]))  # both adapters receive env last
        if '-p' in argv:
            name=argv[argv.index('-p')+1]
            if '--dry-run' in argv:
                target=Path(cwd)/self.dry_dir/(name+'-0.1.0.crate');target.parent.mkdir(parents=True,exist_ok=True)
                original=next(p for p in self.crates if p.name==target.name);shutil.copyfile(original,target)
            else:self.uploaded.add(name)
        else:self.uploaded.add('npm')
        return dict(exit=0,timeout=False,error=None,reaped=True)
    def execute(self):
        approved=dict(eligible=True,head=self.head,version='0.1.0',order=self.inv['order'])
        with patch.dict(os.environ,self.env),patch.object(check,'authorize',return_value=approved),patch.object(check,'checked_command',side_effect=self.command),patch.object(check,'run_command',side_effect=self.command),patch.object(check.urllib.request,'urlopen',side_effect=self.request):
            return check.publish_artifacts(self.root,None)
    def test_mocked_upload_transport(self):
        self.assertEqual(len(self.execute()['published']),12)
    def test_older_cargo_dry_run_location(self):
        self.dry_dir='target/package'
        self.assertEqual(len(self.execute()['published']),12)
    def test_upload_that_shows_up_late_is_waited_for(self):
        request=self.request;misses={'npm':3,'paludarium':2};sleeps=[]
        def late(url,timeout):
            key='npm' if 'npmjs' in url else url.split('/')[-2]
            if key in self.uploaded and misses.get(key):
                misses[key]-=1;raise check.urllib.error.HTTPError(url,404,'not yet',{},None)
            return request(url,timeout)
        self.request=late
        with patch.object(check.time,'sleep',side_effect=sleeps.append):
            self.assertEqual(len(self.execute()['published']),12)
        self.assertEqual(sleeps,[check.UPLOAD_POLL_SECONDS]*5)
    def test_upload_that_never_shows_up_stops(self):
        request=self.request;now=[0]
        def never(url,timeout):
            if 'npmjs' in url and 'npm' in self.uploaded:raise check.urllib.error.HTTPError(url,404,'absent',{},None)
            return request(url,timeout)
        self.request=never
        def sleep(seconds):now[0]+=seconds
        with patch.object(check.time,'sleep',side_effect=sleep),patch.object(check.time,'monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(check.urllib.error.HTTPError):self.execute()
        self.assertGreaterEqual(now[0],check.UPLOAD_VISIBLE_SECONDS)
        progress=json.loads((self.out/'publication-progress.json').read_text())
        self.assertIn('@aletheia-works/paludarium-wasm',progress['uploaded_but_possibly_unverified'])
        self.assertNotIn('@aletheia-works/paludarium-wasm',progress['completed'])
    def test_missing_dry_run_crate_stops_before_upload(self):
        self.dry_dir='target/elsewhere'
        with self.assertRaisesRegex(ValueError,'dry-run crate absent or ambiguous'):self.execute()
        self.assertEqual(self.uploaded,set())
    def test_existing_versions_are_not_uploaded(self):
        self.uploaded=set(self.inv['order'])|{'npm'}
        self.assertEqual(len(self.execute()['published']),12)
    def test_artifact_head_changed_before_upload(self):
        self.result['head']='b'*40;(self.out/'package-result.json').write_text(json.dumps(self.result))
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.uploaded,set())
    def test_npm_digest_changed_before_upload(self):
        self.npm.write_bytes(self.npm.read_bytes()+b'changed')
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.uploaded,set())
    # Trusted Publishing only: the OIDC token reaches the cargo uploads only and is never recorded.
    def test_oidc_token_reaches_uploads_only(self):
        result=self.execute();self.assertNotIn('authentication',result)
        token=CANARY['U15_OIDC_CRATES_IO_TOKEN']
        dry=[e for n,e in self.envs if n.startswith('dry-')];uploads=[e for n,e in self.envs if n.startswith('publish-') and n!='publish-npm']
        npm_env=[e for n,e in self.envs if n=='publish-npm']
        self.assertEqual((len(dry),len(uploads),len(npm_env)),(11,11,1))
        self.assertTrue(all(token not in e.values() for e in dry+npm_env));self.assertTrue(all(e['CARGO_REGISTRY_TOKEN']==token for e in uploads))
        recorded=json.dumps(result)+(self.out/'publication-progress.json').read_text()
        self.assertNotIn(token,recorded)
    def test_missing_oidc_token_stops_before_any_command(self):
        del self.env['U15_OIDC_CRATES_IO_TOKEN']
        with patch.dict(os.environ,{'U15_OIDC_CRATES_IO_TOKEN':''}):
            with self.assertRaisesRegex(ValueError,'OIDC token absent'):self.execute()
        self.assertEqual(self.uploaded,set());self.assertEqual(self.envs,[])
    # Step17 (R-16): resuming a stopped publication uploads only what is missing.
    def test_resume_uploads_only_remaining(self):
        done=self.inv['order'][:3];self.uploaded=set(done)
        result=self.execute();self.assertEqual(result['published'],self.inv['order']+['@aletheia-works/paludarium-wasm'])
        names=[n for n,_ in self.envs]
        self.assertFalse([n for n in names if any(n.endswith('-'+d) for d in done)])
        self.assertEqual(len([n for n in names if n.startswith('publish-') and n!='publish-npm']),8);self.assertIn('publish-npm',names)
        progress=json.loads((self.out/'publication-progress.json').read_text())
        self.assertEqual(progress['attempted'],self.inv['order'][3:]+['@aletheia-works/paludarium-wasm']);self.assertFalse(progress['automatic_retry'])
    # Step24 (review 04, finding 6a): `authorize` is replaced here, so what stops this run is the
    # publish loop's own registry_state check of a present version.
    def test_publish_loop_registry_state_refuses_different_present_digest(self):
        first=self.inv['order'][0];self.uploaded={first}
        request=self.request
        def tampered(url,timeout):
            body=request(url,timeout)
            if url.endswith('/'+first+'/0.1.0'):return io.BytesIO(json.dumps(dict(version=dict(num='0.1.0',checksum='0'*64,yanked=False))).encode())
            return body
        self.request=tampered
        with self.assertRaisesRegex(ValueError,'existing version digest mismatch'):self.execute()
        self.assertEqual(self.uploaded,{first});self.assertEqual(self.envs,[])
    # Step24 (review 04, finding 4): the publish loop never takes a yanked present version as published.
    def test_publish_loop_refuses_yanked_present_version(self):
        first=self.inv['order'][0];self.uploaded={first};self.yanked={first}
        with self.assertRaisesRegex(ValueError,'existing version is yanked'):self.execute()
        self.assertEqual(self.uploaded,{first});self.assertEqual(self.envs,[])
    # Step17 (R-17): the job's GitHub token and OIDC request variables never reach cargo.
    def test_cargo_uploads_never_see_github_or_oidc_request_variables(self):
        self.env.update(GH_TOKEN='canary-gh-0004',ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.invalid',ACTIONS_ID_TOKEN_REQUEST_TOKEN='canary-oidc-request-0006',GITHUB_ACTIONS='true')
        self.execute()
        cargo=[e for n,e in self.envs if n!='publish-npm'];npm=[e for n,e in self.envs if n=='publish-npm'][0]
        self.assertEqual(len(cargo),22)
        self.assertTrue(all(not {'GH_TOKEN','ACTIONS_ID_TOKEN_REQUEST_URL','ACTIONS_ID_TOKEN_REQUEST_TOKEN','GITHUB_ACTIONS'}&set(e) for e in cargo))
        self.assertEqual((npm['ACTIONS_ID_TOKEN_REQUEST_URL'],npm['GITHUB_ACTIONS']),('https://oidc.example.invalid','true'));self.assertNotIn('GH_TOKEN',npm)
    def test_oidc_mode_uses_oidc_token(self):
        self.execute()
        self.assertTrue(all(e['CARGO_REGISTRY_TOKEN']==CANARY['U15_OIDC_CRATES_IO_TOKEN'] for n,e in self.envs if n.startswith('publish-') and n!='publish-npm'))
        self.assertTrue(all('CARGO_REGISTRY_TOKEN' not in e for n,e in self.envs if n.startswith('dry-') or n=='publish-npm'))

if __name__=='__main__':unittest.main()
