"""Release eligibility. Pure checks never create tags, approve jobs or publish."""
import json
import re
import tomllib
from pathlib import Path

PUBLIC = tuple('paludarium-'+n for n in ('types','decoder','mmu','host','vfs','loader','cpu','jit','kernel','runtime'))+('paludarium',)
PRIVATE = {'paludarium-harness','paludarium-wasm'}
REPOSITORY = 'aletheia-works/paludarium'
REQUIRED = {'three-os','lint','dependencies','linux-differential','rust-coverage','js-coverage','u9-coverage','package-check'}
ACCEPTANCE = {'FR6.3','FR7.2','FR7.3','FR8.2','FR8.3'}

def require(value, message):
    if not value:
        raise ValueError(message)

def dependency_order(packages):
    result,active,done=[],set(),set()
    def visit(name):
        require(name in packages,'unknown public dependency: '+name)
        require(name not in active,'dependency cycle: '+name)
        if name in done:return
        active.add(name)
        for dep in sorted(packages[name]['dependencies']):visit(dep)
        active.remove(name);done.add(name);result.append(name)
    for name in sorted(packages):visit(name)
    return result

def inventory(root):
    root=Path(root);workspace=tomllib.loads((root/'Cargo.toml').read_text())['workspace']
    shared=workspace['dependencies'];version=workspace['package']['version'];packages={};private={}
    for member in workspace['members']:
        manifest=tomllib.loads((root/member/'Cargo.toml').read_text());p=manifest['package'];name=p['name']
        require(name not in packages and name not in private,'duplicate package')
        actual=p.get('version');actual=version if actual=={'workspace':True} else actual
        require(actual==version,'workspace version mismatch')
        dependencies={}
        tables=[manifest.get('dependencies',{}),manifest.get('build-dependencies',{})]
        for target in manifest.get('target',{}).values():tables.extend([target.get('dependencies',{}),target.get('build-dependencies',{})])
        for table in tables:
            for alias,dep in table.items():
                if isinstance(dep,str):continue
                dep=shared[alias] if dep.get('workspace') else dep
                require('git' not in dep and dep.get('registry','crates-io')=='crates-io','non-crates.io dependency')
                target=dep.get('package',alias)
                if 'path' in dep:
                    require(target in PUBLIC and dep.get('version')==version,'missing/incorrect public dependency version')
                    dependencies[target]=dep['version']
        row=dict(path=member,name=name,version=actual,dependencies=dependencies,publish=p.get('publish',True),
                 description=p.get('description'),repository=p.get('repository'),readme=p.get('readme'))
        (private if name in PRIVATE else packages)[name]=row
    require(set(packages)==set(PUBLIC) and set(private)==PRIVATE,'public/private package population differs')
    order=dependency_order(packages)
    npm=json.loads((root/'packages/paludarium-wasm/package.json').read_bytes())
    require(npm['name']=='@aletheia-works/paludarium-wasm' and npm['version']==version,'npm identity/version differs')
    return dict(version=version,packages=packages,private=private,order=order,npm=npm)

def protected_environment(environment):
    require(environment.get('name')=='release','release environment absent')
    # Publication needs no person's approval: the same-head evidence gate decides.
    # The environment names the Trusted Publisher, and administrator bypass stays off.
    require(environment.get('can_admins_bypass') is False,'admin protection bypass is enabled/unknown')
    return True

def release_gate(state, manifests):
    require(state.get('repository')==REPOSITORY,'repository is not authorized')
    version=manifests['version']
    require(re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',version) and version!='0.0.0','release version undecided/invalid')
    require(state.get('tag')=='v'+version,'tag/version mismatch')
    commit=state['commit'];head=commit['sha']
    require(re.fullmatch('[0-9a-f]{40}',head),'invalid head')
    require(commit['commit']['verification']['verified'] is True,'head signature unverified')
    compare=state['main_compare']
    require(compare['base_commit']['sha']==head and compare['status'] in ('identical','ahead'),'tag not reachable from main')
    runs=state.get('quality',[])
    require(len(runs)==len(REQUIRED) and {r['purpose'] for r in runs}==REQUIRED,'missing/duplicate quality evidence')
    for run in runs:
        require(run['repository']==REPOSITORY and run['head_sha']==head and run['status']=='completed' and run['conclusion']=='success','quality failed/unfinished/wrong source')
        require(type(run['id']) is int and run['id']>0,'invalid run identity')
    evidence=state.get('acceptance',[])
    require({e['id'] for e in evidence}==ACCEPTANCE and len(evidence)==len(ACCEPTANCE),'missing acceptance condition')
    for e in evidence:require(e['head']==head and e['passed'] is True and re.fullmatch('[0-9a-f]{64}',e['artifact_sha256']),'acceptance unverified')
    protected_environment(state.get('environment',{}))
    return dict(eligible=True,head=head,version=version,order=manifests['order'])
