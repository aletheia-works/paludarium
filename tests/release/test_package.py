import io,json,sys,tarfile,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts/release'))
import package,policy

def tar(path,files,prefix='package',extra=None):
    with tarfile.open(path,'w:gz') as a:
        for name,raw in files.items():
            info=tarfile.TarInfo(prefix+'/'+name);info.size=len(raw);a.addfile(info,io.BytesIO(raw))
        if extra:
            info,raw=extra;a.addfile(info,io.BytesIO(raw))

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'target/u15');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'npm.tgz'
        self.files={n:b'export {};' for n in package.REQUIRED_JS}
        self.files.update({'package.json':json.dumps(dict(name='@aletheia-works/paludarium-wasm',version='0.0.0')).encode(),
          'index.d.ts':b'export {};','paludarium.wasm':b'\0asm\x01\0\0\0','LICENSE':b'Apache-2.0','README.md':b'usage'})
    def inspect(self,extra=None,expected_change=None):
        tar(self.path,self.files,extra=extra)
        expected=dict(tar_sha256=package.sha(self.path.read_bytes()),wasm_sha256=package.sha(b'\0asm\x01\0\0\0'),
            version='0.0.0',head='a'*40,source_sha256='b'*64,source_files={})
        if expected_change:expected.update(expected_change)
        return package.inspect_npm(self.path,expected)
    def test_valid_npm(self):self.assertEqual(len(self.inspect()['files']),11)
    def test_jit_support_missing(self):
        del self.files['jit-support.mjs']
        with self.assertRaises(ValueError):self.inspect()
    def test_wasm_missing(self):
        del self.files['paludarium.wasm']
        with self.assertRaises(ValueError):self.inspect()
    def test_wasm_changed(self):
        self.files['paludarium.wasm']+=b'changed'
        with self.assertRaises(ValueError):self.inspect()
    def test_second_wasm(self):
        self.files['diagnostic.wasm']=b'\0asm\x01\0\0\0'
        with self.assertRaises(ValueError):self.inspect()
    def test_missing_import(self):
        self.files['index.mjs']=b'import "./absent.mjs";'
        with self.assertRaises(ValueError):self.inspect()
    def test_duplicate(self):
        item=tarfile.TarInfo('package/index.mjs');item.size=1
        with self.assertRaises(ValueError):self.inspect((item,b'x'))
    def test_escape(self):
        item=tarfile.TarInfo('package/../escape');item.size=1
        with self.assertRaises(ValueError):self.inspect((item,b'x'))
    def test_link(self):
        item=tarfile.TarInfo('package/link');item.type=tarfile.SYMTYPE;item.linkname='/outside'
        with self.assertRaises(ValueError):self.inspect((item,b''))
    def test_source_changed(self):
        with self.assertRaises(ValueError):self.inspect(expected_change=dict(source_files={'index.mjs':'0'*64}))
    def test_tar_changed(self):
        with self.assertRaises(ValueError):self.inspect(expected_change=dict(tar_sha256='0'*64))
    def test_wrong_version(self):
        with self.assertRaises(ValueError):self.inspect(expected_change=dict(version='1.0.0'))
    def crates(self,change=None):
        # Fixtures follow the real manifest version, so a version change cannot
        # make the rejection cases pass for an unrelated file-name reason.
        inventory=policy.inventory(ROOT);paths=[];version=inventory['version']
        for name in inventory['order']:
            row=inventory['packages'][name]
            deps='\n'.join('[dependencies.'+d+']\nversion = "'+v+'"' for d,v in row['dependencies'].items())
            metadata='[package]\nname="'+name+'"\nversion="'+version+'"\nlicense="Apache-2.0"\n'+deps
            files={'Cargo.toml':metadata.encode(),'LICENSE':b'Apache','README.md':b'usage'}
            if change:change(name,files)
            p=self.root/(name+'-'+version+'.crate');tar(p,files,name+'-'+version);paths.append(p)
        return paths,inventory
    def test_eleven_crates(self):
        paths,inv=self.crates();self.assertEqual(len(package.inspect_crates(paths,inv)),11)
    def test_dependency_version(self):
        def change(name,files):
            if name=='paludarium-decoder':
                text=files['Cargo.toml'].decode();line='version = "'+policy.inventory(ROOT)['version']+'"'
                self.assertIn(line,text);files['Cargo.toml']=text.replace(line,'version = "9.0.0"').encode()
        paths,inv=self.crates(change)
        with self.assertRaisesRegex(ValueError,'dependency missing/version mismatch'):package.inspect_crates(paths,inv)
    def test_private_crate(self):
        paths,inv=self.crates();paths[-1]=self.root/('paludarium-harness-'+inv['version']+'.crate')
        with self.assertRaises(ValueError):package.inspect_crates(paths,inv)
    def test_missing_crate(self):
        paths,inv=self.crates()
        with self.assertRaises(ValueError):package.inspect_crates(paths[:-1],inv)

if __name__=='__main__':unittest.main()
