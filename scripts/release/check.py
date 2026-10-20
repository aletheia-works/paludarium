"""Non-publishing release checks and bounded, retained command evidence."""
import argparse,base64,hashlib,json,os,signal,subprocess,sys,time,urllib.error,urllib.request
from pathlib import Path
import policy
import package

ROOT=Path(__file__).resolve().parents[2]

def snapshot(root,paths):
    return {str(p):package.sha((root/p).read_bytes()) for p in paths}

def run_command(argv,cwd,output,timeout=120,env=None):
    policy.require(isinstance(argv,list) and bool(argv) and all(isinstance(v,str) for v in argv),'invalid argv')
    policy.require(Path(argv[0]).is_absolute() and '/shims/' not in argv[0],'actual tool path required')
    policy.require(0<timeout<=900,'invalid timeout')
    output=Path(output);output.mkdir()
    started=time.monotonic();proc=None;timed_out=False;cleanup=[];error=None
    with (output/'stdout.bin').open('xb') as stdout,(output/'stderr.bin').open('xb') as stderr:
        try:
            proc=subprocess.Popen(argv,cwd=cwd,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
            try:proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                try:os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
                cleanup.append('owned process group terminated and reaped')
        except OSError as e:error=str(e)
    streams={}
    for name in ('stdout','stderr'):
        p=output/(name+'.bin');raw=p.read_bytes()
        streams[name]=dict(bytes=len(raw),sha256=package.sha(raw))
    receipt=dict(argv=argv,cwd=str(Path(cwd).resolve()),exit=proc.returncode if proc else None,
       timeout=timed_out,error=error,reaped=proc is None or proc.poll() is not None,
       seconds=time.monotonic()-started,cleanup=cleanup,streams=streams,
       tool_sha256=package.sha(Path(argv[0]).read_bytes()) if Path(argv[0]).is_file() else None)
    selected=env if env is not None else os.environ
    receipt['tool_environment']={k:selected[k] for k in ('RUSTC','RUSTDOC','RUSTUP_TOOLCHAIN','RUSTFLAGS','CARGO_HOME','PALUDARIUM_TEST_NODE','PALUDARIUM_RELEASE_NPM') if k in selected}
    receipt['compiler_inputs']={k:dict(path=selected[k],sha256=package.sha(Path(selected[k]).read_bytes())) for k in ('RUSTC','RUSTDOC') if k in selected and Path(selected[k]).is_file()}
    with (output/'receipt.json').open('x') as f:json.dump(receipt,f,indent=2)
    return receipt

def require_success(receipt):
    policy.require(receipt['exit']==0 and receipt['timeout'] is False and receipt['error'] is None and receipt['reaped'] is True,'command failed/incomplete')

def checked_command(argv,cwd,output,paths,timeout=120,env=None):
    before=snapshot(Path(cwd),paths)
    receipt=run_command(argv,cwd,output,timeout,env)
    after=snapshot(Path(cwd),paths)
    with (Path(output)/'inputs.json').open('x') as f:json.dump(dict(before=before,after=after),f,indent=2)
    policy.require(before==after,'command changed protected inputs')
    require_success(receipt)
    return receipt

def registry_state(status,body,version,digest):
    if status==404:return dict(state='UNPUBLISHED',upload_allowed=False)
    policy.require(status==200,'registry query failed; publication status unknown')
    policy.require(isinstance(body,dict) and body.get('version')==version,'registry returned different version')
    policy.require(body.get('digest')==digest,'existing version digest mismatch')
    # Step24 (review 04, finding 4): a yanked version never counts as the published release.
    policy.require(body.get('yanked') is not True,'existing version is yanked')
    return dict(state='PUBLISHED_MATCH',upload_allowed=False)

def publish_sequence(state,inventory,upload,verify):
    """Adapter boundary tested with mocks; CLI never invokes upload."""
    eligible=policy.release_gate(state,inventory);completed=[]
    for name in eligible['order']+['@aletheia-works/paludarium-wasm']:
        result=upload(name,eligible['version'])
        policy.require(result.get('published') is True,'upload failed; later uploads stopped')
        completed.append(name)
        policy.require(verify(name,result) is True,'post-publication digest/provenance mismatch')
    return completed

def validate(root):
    inv=policy.inventory(root)
    for row in inv['packages'].values():
        policy.require(bool(row['description']) and bool(row['repository']) and bool(row['readme']),'public metadata incomplete: '+row['name'])
    policy.require(all(row['publish'] is False for row in inv['private'].values()),'private package is publishable')
    for name in ['release-check.yml','publish.yml']:
        text=(root/'.github/workflows'/name).read_text()
        policy.require('persist-credentials: false' in text and 'timeout-minutes:' in text,'workflow isolation/timeout absent')
        import re
        actions=re.findall(r'uses:\s+([^\s#]+)',text)
        policy.require(bool(actions) and all(a.startswith('./') or re.fullmatch(r'[^@]+@[0-9a-f]{40}',a) for a in actions),'unpinned workflow action')
    outstanding=['Trusted Publishers','release environment','same-head acceptance evidence']
    if inv['version']=='0.0.0':outstanding.insert(0,'release version')
    return dict(validated=True,version=inv['version'],crates=11,publish_eligible=False,outstanding=outstanding)

def rustup_toolchains():
    """The toolchains rustup installed: RUSTUP_HOME when set (CI uses a job-local one), else ~/.rustup."""
    return Path(os.environ.get('RUSTUP_HOME') or Path.home()/'.rustup')/'toolchains'

REGISTRY_USER_AGENT='paludarium-release (https://github.com/aletheia-works/paludarium)'
CRATES_API='https://crates.io/api/v1/crates/'
NPM_NAME='@aletheia-works/paludarium-wasm'
NPM_PACKAGE_URL='https://registry.npmjs.org/%40aletheia-works%2Fpaludarium-wasm'
CARGO_TOKEN_NAMES=('CARGO_REGISTRY_TOKEN','U15_OIDC_CRATES_IO_TOKEN')
# Step17 (R-17): each publication child gets only the variables it needs (allow-list).
COMMON_ENVIRONMENT=('PATH','HOME','TMPDIR','LANG','LC_ALL','TZ','SSL_CERT_FILE','SSL_CERT_DIR',
    'HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy')
# cargo never gets GH_TOKEN, GITHUB_TOKEN or ACTIONS_ID_TOKEN_REQUEST_*.
CARGO_ENVIRONMENT=COMMON_ENVIRONMENT+('CARGO_HOME','RUSTUP_HOME','RUSTUP_TOOLCHAIN','RUSTC','RUSTDOC','RUSTFLAGS','CARGO_TERM_COLOR')
# npm publish --provenance on GitHub Actions: ci detection, the OIDC request for
# provenance signing and Trusted Publishing, and the GitHub context the provenance
# statement names. NPM_CONFIG_USERCONFIG/NODE_AUTH_TOKEN are setup-node's .npmrc
# and its placeholder; Trusted Publishing needs no token.
NPM_ENVIRONMENT=COMMON_ENVIRONMENT+('CI','GITHUB_ACTIONS','ACTIONS_ID_TOKEN_REQUEST_URL','ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'GITHUB_SERVER_URL','GITHUB_REPOSITORY','GITHUB_REPOSITORY_ID','GITHUB_REPOSITORY_OWNER_ID','GITHUB_WORKFLOW_REF',
    'GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT',
    'NPM_CONFIG_USERCONFIG','NODE_AUTH_TOKEN')

def registry_request(url):
    return urllib.request.Request(url,headers={'User-Agent':REGISTRY_USER_AGENT,'Accept':'application/json'})

def registry_present(url):
    """True/False for 200/404; any other answer leaves presence unknown and stops."""
    try:
        with urllib.request.urlopen(registry_request(url),timeout=30) as response:response.read(1)
    except urllib.error.HTTPError as error:
        if error.code==404:return False
        raise ValueError('registry query failed; presence unknown: %d %s'%(error.code,url)) from error
    except urllib.error.URLError as error:raise ValueError('registry unreachable; presence unknown: '+url) from error
    return True

def registry_version(url):
    """Parsed body for 200 ({} when unparseable), None for 404; any other answer stops."""
    try:
        with urllib.request.urlopen(registry_request(url),timeout=30) as response:raw=response.read(16*1024*1024)
    except urllib.error.HTTPError as error:
        if error.code==404:return None
        raise ValueError('registry query failed; version state unknown: %d %s'%(error.code,url)) from error
    except urllib.error.URLError as error:raise ValueError('registry unreachable; version state unknown: '+url) from error
    try:body=json.loads(raw)
    except ValueError:return {}
    return body if isinstance(body,dict) else {}

def registry_presence(order):
    """Which of the eleven crate names and @aletheia-works/paludarium-wasm exist on their registry."""
    urls={name:CRATES_API+name for name in order}
    urls[NPM_NAME]=NPM_PACKAGE_URL
    return dict(present=sorted(name for name,url in sorted(urls.items()) if registry_present(url)),checked=sorted(urls))

def npm_integrity(raw):
    return 'sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode()

def allowed(environ,names,**extra):
    return dict({k:environ[k] for k in names if k in environ},**extra)

def publication_environments(environ):
    """(dry-run, cargo upload, npm upload) child environments, built from allow-lists.
    Only the cargo upload gets the short-lived crates.io OIDC token; npm uses Trusted
    Publishing itself and dry runs get none. Values never enter results, receipts or
    progress records (receipts keep only whitelisted non-secret keys)."""
    oidc=environ.get('U15_OIDC_CRATES_IO_TOKEN','')
    policy.require(bool(oidc),'crates.io OIDC token absent')
    return allowed(environ,CARGO_ENVIRONMENT),allowed(environ,CARGO_ENVIRONMENT,CARGO_REGISTRY_TOKEN=oidc),allowed(environ,NPM_ENVIRONMENT)

def github(route):
    token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    policy.require(bool(token),'GitHub read token unavailable')
    request=urllib.request.Request('https://api.github.com/repos/'+policy.REPOSITORY+'/'+route,
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
    try:
        with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)
    except urllib.error.HTTPError as error:raise ValueError('GitHub evidence unavailable: '+str(error.code)) from error

def preflight(root):
    inv=policy.inventory(root);version=inv['version']
    policy.require(os.environ.get('GITHUB_REPOSITORY')==policy.REPOSITORY,'publishing from fork is forbidden')
    policy.require(version!='0.0.0','release version not decided')
    # Publish first, tag last: the release runs on main, and its tag must not exist yet.
    policy.require(os.environ.get('GITHUB_REF')=='refs/heads/main','publication runs only on main')
    refs=github('git/matching-refs/tags/v'+version)
    policy.require(not any(r.get('ref')=='refs/tags/v'+version for r in refs),'v'+version+' is already tagged')
    head=os.environ['GITHUB_SHA'];commit=github('commits/'+head)
    policy.require(commit['sha']==head and commit['commit']['verification']['verified'] is True,'unsigned head')
    compare=github('compare/'+head+'...main')
    policy.require(compare['base_commit']['sha']==head and compare['status'] in ('ahead','identical'),'head not reachable from main')
    environment=github('environments/release');policy.protected_environment(environment)
    return dict(preflight=True,head=head,version=version,environment=environment)

def authorize(root,evidence):
    policy.require(os.environ.get('GITHUB_ACTIONS')=='true','publication authorization is CI-only')
    pre=preflight(root);policy.require(evidence is not None and evidence.is_file(),'same-head acceptance evidence artifact missing')
    state=json.loads(evidence.read_bytes());head=pre['head']
    state.update(repository=policy.REPOSITORY,tag='v'+pre['version'],commit=github('commits/'+head),
        main_compare=github('compare/'+head+'...main'),environment=pre['environment'])
    for row in state.get('quality',[]):
        actual=github('actions/runs/'+str(row['id']))
        policy.require(actual['head_sha']==row['head_sha'] and actual['repository']['full_name']==row['repository'] and
            actual['status']==row['status'] and actual['conclusion']==row['conclusion'],'official quality run differs')
    return policy.release_gate(state,policy.inventory(root))

def fetch_acceptance(root):
    """Only an official successful, same-head acceptance artifact is eligible."""
    import io,zipfile
    head=os.environ['GITHUB_SHA'];runs=github('actions/runs?head_sha='+head+'&status=success&per_page=100')
    policy.require(runs.get('total_count',0)<=100,'acceptance run pagination required; refusing incomplete listing')
    candidates=[]
    for run in runs['workflow_runs']:
        if run['head_sha']!=head or run['repository']['full_name']!=policy.REPOSITORY:continue
        catalog=github('actions/runs/'+str(run['id'])+'/artifacts?per_page=100')
        policy.require(catalog['total_count']<=100,'artifact pagination required')
        candidates.extend(a for a in catalog['artifacts'] if a['name']=='u15-acceptance' and not a['expired'])
    policy.require(len(candidates)==1,'same-head reviewed u15-acceptance artifact absent/ambiguous')
    artifact=candidates[0];policy.require(artifact['workflow_run']['head_sha']==head,'acceptance artifact wrong source')
    token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    request=urllib.request.Request(artifact['archive_download_url'],headers={'Accept':'application/vnd.github+json'})
    # GitHub answers with a redirect to a pre-signed storage URL that rejects any
    # Authorization header, so the token goes to the API request only.
    request.add_unredirected_header('Authorization','Bearer '+token)
    with urllib.request.urlopen(request,timeout=30) as response:raw=response.read(64*1024*1024+1)
    policy.require(len(raw)<=64*1024*1024 and artifact['digest']=='sha256:'+package.sha(raw),'official acceptance ZIP digest differs')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        policy.require(archive.namelist()==['release-evidence.json'],'acceptance archive population differs')
        data=json.loads(archive.read('release-evidence.json'))
    policy.require(data['head']==head,'acceptance document wrong head')
    return data

UPLOAD_VISIBLE_SECONDS=15*60
UPLOAD_POLL_SECONDS=15

def uploaded_metadata(url,sleep=None,clock=None):
    """A just-uploaded version can stay 404 for minutes (a new npm package took five), so wait for it."""
    sleep=sleep or time.sleep;clock=clock or time.monotonic;deadline=clock()+UPLOAD_VISIBLE_SECONDS
    while True:
        try:
            with urllib.request.urlopen(url,timeout=30) as response:return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code!=404 or clock()>=deadline:raise
        sleep(UPLOAD_POLL_SECONDS)

def dry_run_crate(source,name,version):
    # Current Cargo writes the dry-run crate to target/package/tmp-crate/; older Cargo to target/package/.
    file=name+'-'+version+'.crate'
    found=[p for p in (source/'target/package/tmp-crate'/file,source/'target/package'/file) if p.is_file()]
    policy.require(len(found)==1,'dry-run crate absent or ambiguous: '+file+'; no upload allowed')
    return found[0]

def publish_artifacts(root,evidence):
    """Reachable only in the CI publish job on main, after the same-head evidence."""
    import zipfile
    approved=authorize(root,evidence);directory=root/'target/u15'
    result=json.loads((directory/'package-result.json').read_bytes())
    policy.require(result['passed'] is True and result['head']==approved['head'] and result['local_snapshot'] is False,'package artifact wrong head/result')
    crates=list(directory.glob('**/source/target/package/*.crate'));inventory=policy.inventory(root)
    actual=package.inspect_crates(crates,inventory)
    policy.require(actual==result['crates'],'prepared crates changed')
    tarballs=list(directory.glob('package-*/*.tgz'));policy.require(len(tarballs)==1,'npm artifact absent/ambiguous')
    expected=dict(version=approved['version'],head=approved['head'],source_sha256=result['source_sha256'],tar_sha256=result['npm']['tar_sha256'],
                  wasm_sha256=result['npm']['wasm_sha256'],source_files={n:r['sha256'] for n,r in result['npm']['files'].items() if n in package.REQUIRED_JS})
    package.inspect_npm(tarballs[0],expected)
    archives=list(directory.glob('package-*/source-snapshot.zip'));policy.require(len(archives)==1,'source snapshot ambiguous')
    source=root/'target/u15/publish-source';source.mkdir()
    with zipfile.ZipFile(archives[0]) as archive:
        names=archive.namelist();policy.require(len(names)==len(set(names)),'source snapshot duplicate')
        for name in names:
            path=Path(name);policy.require(not path.is_absolute() and '..' not in path.parts and '\\' not in name,'unsafe source snapshot')
            target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(name))
    policy.require(package.sha(json.dumps(snapshot(source,[Path(n) for n in names]),sort_keys=True).encode())==result['source_sha256'],'source snapshot differs')
    toolchain=__import__('tomllib').loads((source/'rust-toolchain.toml').read_text())['toolchain']['channel']
    cargos=list(rustup_toolchains().glob(toolchain+'-*/bin/cargo'));policy.require(len(cargos)==1,'actual pinned Cargo absent')
    cargo=cargos[0];env=dict(os.environ,RUSTC=str(cargo.with_name('rustc')),RUSTDOC=str(cargo.with_name('rustdoc')),PATH=str(cargo.parent)+os.pathsep+os.environ['PATH'])
    dry_env,cargo_env,npm_env=publication_environments(env)
    completed=[];attempted=[];uploaded=[]
    try:
        for name in approved['order']:
            try:
                with urllib.request.urlopen('https://crates.io/api/v1/crates/'+name+'/'+approved['version'],timeout=30) as response:existing=json.load(response)
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
            else:
                registry_state(200,dict(version=existing['version']['num'],digest=existing['version']['checksum'],yanked=existing['version'].get('yanked')),approved['version'],actual[name]['sha256'])
                completed.append(name);continue
            # Dry-run reassembly must match the previously checked artifact.
            checked_command([str(cargo),'publish','--locked','--dry-run','--no-verify','--manifest-path',str(source/'Cargo.toml'),'-p',name],source,directory/('dry-'+name),[Path(n) for n in names],900,dry_env)
            candidate=dry_run_crate(source,name,approved['version'])
            policy.require(package.sha(candidate.read_bytes())==actual[name]['sha256'],'publish reassembly changed; no upload allowed')
            attempted.append(name)
            checked_command([str(cargo),'publish','--locked','--no-verify','--manifest-path',str(source/'Cargo.toml'),'-p',name],source,directory/('publish-'+name),[Path(n) for n in names],900,cargo_env)
            uploaded.append(name)
            body=uploaded_metadata('https://crates.io/api/v1/crates/'+name+'/'+approved['version'])
            registry_state(200,dict(version=body['version']['num'],digest=body['version']['checksum'],yanked=body['version'].get('yanked')),approved['version'],actual[name]['sha256'])
            completed.append(name)
        node=Path(os.environ['PALUDARIUM_TEST_NODE']);npm=Path(os.environ['PALUDARIUM_RELEASE_NPM'])
        integrity=npm_integrity(tarballs[0].read_bytes())
        url=NPM_PACKAGE_URL+'/'+approved['version']
        try:
            with urllib.request.urlopen(url,timeout=30) as response:body=json.load(response)
        except urllib.error.HTTPError as error:
            if error.code!=404:raise
            attempted.append('@aletheia-works/paludarium-wasm')
            require_success(run_command([str(node),str(npm),'publish',str(tarballs[0]),'--access','public','--provenance','--ignore-scripts'],root,directory/'publish-npm',120,npm_env))
            uploaded.append('@aletheia-works/paludarium-wasm')
            body=uploaded_metadata(url)
        registry_state(200,dict(version=body['version'],digest=body['dist']['integrity']),approved['version'],integrity)
        completed.append('@aletheia-works/paludarium-wasm')
        return dict(published=completed,head=approved['head'],version=approved['version'])
    finally:
        with (directory/'publication-progress.json').open('x') as f:json.dump(dict(completed=completed,attempted=attempted,uploaded_but_possibly_unverified=uploaded,automatic_retry=False),f,indent=2)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['validate','package-check','preflight','authorize','fetch-acceptance','publish'],required=True)
    parser.add_argument('--output',type=Path);parser.add_argument('--evidence',type=Path)
    args=parser.parse_args()
    if args.mode=='validate':result=validate(ROOT)
    elif args.mode=='package-check':
        from package import package_check
        result=package_check(ROOT)
    elif args.mode=='preflight':result=preflight(ROOT)
    elif args.mode=='authorize':result=authorize(ROOT,args.evidence)
    elif args.mode=='fetch-acceptance':result=fetch_acceptance(ROOT)
    else:result=publish_artifacts(ROOT,args.evidence)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x') as f:json.dump(result,f,indent=2)
    print(json.dumps(result))

if __name__=='__main__':main()
