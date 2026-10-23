"""Reject mutation false positives, stale anchors, and vacuous or unfinished native test streams."""

import base64
import copy
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

from tools import mutate, verify


class MutationTests(unittest.TestCase):
    """Keep compiled-test failures separate from compile errors, skips, timeouts, and survivors."""

    def test_deletion(self) -> None:
        """A real statement may be deleted; empty, ambiguous or unchanged anchors still cannot form a plan."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "value.go"
            data = "package example\nfunc Value() int { value := 1; value = 2; return value }\n"
            source.write_text(data, encoding="utf-8")
            manifest = {
                "version": 1,
                "scope": "Planner-only deletion controls; no compilation or mutation qualification.",
                "package": "./example",
                "import": "example",
                "mutations": [{"id": "delete", "file": "value.go", "test": "TestValue", "before": "value = 2; ", "after": ""}],
            }
            planned = mutate.plan(manifest, root)
            self.assertEqual(len(planned), 1)
            self.assertEqual(planned[0]["replacement"], data.replace("value = 2; ", ""))
            self.assertEqual(source.read_text(encoding="utf-8"), data)
            for before, after in (("", ""), ("value", ""), ("value = 2; ", "value = 2; ")):
                changed = copy.deepcopy(manifest)
                changed["mutations"][0].update(before=before, after=after)
                with self.subTest(before=before, after=after), self.assertRaises(verify.Invalid):
                    mutate.plan(changed, root)

    def test_observations(self) -> None:
        """Challenge the gate's reconstruction with synthetic facts; these are not product mutation evidence."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "value.go").write_text("package example\nfunc Value() int { return 1 }\n", encoding="utf-8")
            manifest = {
                "version": 1,
                "scope": "One artificial mutation for evidence-parser negative controls.",
                "package": "./example",
                "import": "example",
                "mutations": [{"id": "value", "file": "value.go", "test": "TestValue", "before": "return 1", "after": "return 2"}],
            }
            (root / "manifest.json").write_bytes(verify.encode(manifest))
            check = {"adapter": "go-mutations", "manifest": "manifest.json", "log_bytes": 1024**2, "probes": [{"contract": "FIXTURE", "minimum_hits": 1}]}
            planned = mutate.plan(manifest, root)[0]
            rows = [{"event": "start", "manifest_sha256": verify.file_digest(root / "manifest.json"), "sources": {"value.go": planned["source_sha256"]}}]
            for name, state in (("baseline-TestValue", "pass"), ("value", "fail")):
                data = b"\n".join(
                    json.dumps(entry).encode()
                    for entry in [
                        {"Package": "example", "Action": "run", "Test": "TestValue"},
                        {"Package": "example", "Action": state, "Test": "TestValue"},
                        {"Package": "example", "Action": state},
                    ]
                )
                environment = {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly"}
                environment["TMPDIR"] = "/fixture/source/build/" + name + "/tmp"
                argv = ["/fixture/go", "test", "-json", "-count=1", "-p=2", "-parallel=1", "-timeout=180s", "-run=^TestValue$"]
                if name == "value":
                    argv.append("-overlay=/fixture/source/build/value.json")
                argv.append("./example")
                record = {
                    "id": name,
                    "platform": "linux-amd64-cgo",
                    "argv": argv,
                    "environment": environment,
                    "resolved_environment": environment,
                    "executable": "/fixture/go",
                    "executable_sha256": "e" * 64,
                    "toolchain": {"command": {"path": "/fixture/go", "sha256": "e" * 64}},
                    "started_at": "2026-10-02T00:00:00Z",
                    "finished_at": "2026-10-02T00:00:01Z",
                    "duration_ms": 1000,
                    "exit_code": 0 if state == "pass" else 1,
                    "termination": "exited",
                    "complete": True,
                    "cleanup": True,
                    **{field: {"path": field + ".log", "sha256": verify.digest(raw), "bytes": len(raw)} for field, raw in (("stdout", data), ("stderr", b""))},
                }
                rows.append(
                    {
                        "event": "result",
                        "id": name,
                        "record": record,
                        "stdout": base64.b64encode(data).decode(),
                        "stderr": "",
                        "overlay": {"Replace": {"/fixture/source/value.go": "/fixture/source/build/value.go.txt"}} if name == "value" else None,
                        "replacement_sha256": verify.digest(planned["replacement"].encode()) if name == "value" else None,
                    }
                )
            rows.append({"event": "finish", "source_unchanged": True, "interrupted": False})

            def parse(values: list[dict]) -> tuple[dict[str, int], list[str]]:
                """Keep the recorded Linux root independent of this reader's actual host and source directory."""
                data = b"\n".join(b"ASTRA-MUTATION " + json.dumps(value).encode() for value in values)
                return mutate.observations(data, check, root, origin="/fixture/source")

            self.assertEqual(parse(rows), ({"FIXTURE": 1}, []))
            data = b"\n".join(b"ASTRA-MUTATION " + json.dumps(value).encode() for value in rows)
            for origin in ("fixture/source", "//fixture/source", "/fixture/../source", "/fixture//source", "C:\\fixture\\source", "/fixture/wrong"):
                with self.subTest(origin=origin), self.assertRaises(verify.Invalid):
                    mutate.observations(data, check, root, origin=origin)
            for temporary in (
                "/outside/value/tmp",
                "/fixture/source/build/../value/tmp",
                "/fixture/source/build/other/tmp",
                "/fixture/source/build/new/value/tmp",
            ):
                changed = copy.deepcopy(rows)
                changed[2]["record"]["resolved_environment"]["TMPDIR"] = temporary
                with self.subTest(temporary=temporary), self.assertRaisesRegex(verify.Invalid, "mutation-temporary-boundary"):
                    parse(changed)
            for changed in (rows[:-1], rows[:2] + rows[3:], rows[:2] + rows[1:]):
                with self.assertRaises(verify.Invalid):
                    parse(changed)
            for index, field, value in [
                (0, "manifest_sha256", "f" * 64),
                (2, "id", "other"),
                (2, "replacement_sha256", "a" * 64),
                (2, "overlay", {"Replace": {}}),
                (2, "stdout", "garbage!"),
                (2, "stderr", "YQ=="),
                (3, "source_unchanged", False),
                (3, "source_unchanged", 1),
                (3, "interrupted", True),
                (3, "interrupted", 0),
            ]:
                changed = copy.deepcopy(rows)
                changed[index][field] = value
                with self.subTest(field=field), self.assertRaises(verify.Invalid):
                    parse(changed)
            for field, value in [("argv", ["go", "test"]), ("id", "other"), ("duration_ms", 240001)]:
                changed = copy.deepcopy(rows)
                changed[2]["record"][field] = value
                with self.subTest(field=field), self.assertRaises(verify.Invalid):
                    parse(changed)
            for field, value in [("exit_code", 0), ("cleanup", False), ("complete", False), ("termination", "timeout")]:
                changed = copy.deepcopy(rows)
                changed[2]["record"][field] = value
                observed, failures = parse(changed)
                self.assertEqual(observed, {})
                self.assertTrue(failures)
            changed = copy.deepcopy(rows)
            changed[1]["record"]["exit_code"] = 1
            self.assertTrue(parse(changed)[1])
            # A internally consistent passing stream is a survivor, not a killed mutation.
            changed = copy.deepcopy(rows)
            changed[2]["stdout"] = rows[1]["stdout"]
            changed[2]["record"]["stdout"] = rows[1]["record"]["stdout"]
            changed[2]["record"]["exit_code"] = 0
            self.assertEqual(parse(changed), ({}, ["value:survived"]))
            (root / "value.go").write_text("package example\nfunc Value() int { return 1 /* drift */ }\n", encoding="utf-8")
            with self.assertRaisesRegex(verify.Invalid, "mutation-stream-plan"):
                parse(rows)

            # Added oracles bind their bytes and both overlay phases; historical streams stay strict.
            (root / "value.go").write_text("package example\nfunc Value() int { return 1 }\n", encoding="utf-8")
            (root / "example").mkdir()
            (root / "oracle.go.in").write_text("package example\n", encoding="utf-8")
            manifest["fixtures"] = [{"source": "oracle.go.in", "target": "example/oracle_test.go"}]
            (root / "manifest.json").write_bytes(verify.encode(manifest))
            oracles = mutate.fixtures(manifest, root)
            joined = copy.deepcopy(rows)
            joined[0]["manifest_sha256"] = verify.file_digest(root / "manifest.json")
            joined[0]["fixtures"] = [{key: val for key, val in item.items() if key != "data"} for item in oracles]
            for item in joined[1:-1]:
                if item["overlay"] is None:
                    item["overlay"] = {"Replace": {}}
                    item["record"]["argv"].insert(-1, "-overlay=/fixture/source/build/" + item["id"] + ".json")
                item["overlay"]["Replace"]["/fixture/source/example/oracle_test.go"] = "/fixture/source/build/fixture-0.go.txt"
            self.assertEqual(parse(joined), ({"FIXTURE": 1}, []))
            missing = copy.deepcopy(joined)
            del missing[0]["fixtures"]
            with self.assertRaises(verify.Invalid):
                parse(missing)
            for index in (1, 2):
                missing = copy.deepcopy(joined)
                del missing[index]["overlay"]["Replace"]["/fixture/source/example/oracle_test.go"]
                with self.subTest(phase=index), self.assertRaises(verify.Invalid):
                    parse(missing)
            for field, value in [("sha256", "f" * 64), ("source", "different.go.in"), ("target", "example/value.go")]:
                changed = copy.deepcopy(joined)
                changed[0]["fixtures"][0][field] = value
                with self.subTest(field=field), self.assertRaises(verify.Invalid):
                    parse(changed)
            (root / "oracle.go.in").write_text("package different\n", encoding="utf-8")
            with self.assertRaisesRegex(verify.Invalid, "mutation-stream-plan"):
                parse(joined)

    @staticmethod
    def environment() -> dict[str, str]:
        """Select the existing approved MSVC/SDK installation only for native fixture children."""
        values = dict(os.environ)
        if os.name == "nt":
            compiler = Path("C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/14.51.36231")
            sdk = Path("C:/Program Files (x86)/Windows Kits/10")
            version = "10.0.22621.0"
            includes = [compiler / "include", *(sdk / "Include" / version / name for name in ("ucrt", "shared", "um"))]
            libraries = [compiler / "lib/x64", *(sdk / "Lib" / version / name / "x64" for name in ("ucrt", "um"))]
            if not (compiler / "bin/Hostx64/x64/cl.exe").is_file() or not all(path.is_dir() for path in includes + libraries):
                raise RuntimeError("Missing existing MSVC 14.51.36231 or Windows SDK 10.0.22621.0; fixtures never install tools")
            values.update(CXX=str(compiler / "bin/Hostx64/x64/cl.exe"), INCLUDE=os.pathsep.join(map(str, includes)), LIB=os.pathsep.join(map(str, libraries)))
            values["PATH"] = str(compiler / "bin/Hostx64/x64") + os.pathsep + values.get("PATH", "")
        return values

    @unittest.skipUnless(platform.system() in {"Linux", "Windows"}, "Existing offline native C++ compiler")
    def test_cpp_execution(self) -> None:
        """Exercise native compile, archive, link, assertion rejection and owned cleanup before trusting the C++ campaign."""
        root = Path(__file__).resolve().parents[1]
        temporary = root / "build/mutation-fixtures"
        temporary.mkdir(parents=True, exist_ok=True)
        script = """
import ctypes,json,os,pathlib,sys
from tools import build,mutate,verify as v
if os.name!='nt': assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
root=pathlib.Path(sys.argv[1]); fixture=pathlib.Path(sys.argv[2])
# This child owns a separate fixture Git tree and cache; never reuse the campaign's private source index.
for key in ('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE'):
    os.environ.pop(key,None)
build.ROOT=fixture
source=fixture/'common/src/value.cpp'; source.parent.mkdir(parents=True)
source.write_text('int value() { return 1; }\\n')
oracle=fixture/'common/tests/value_test.cpp'; oracle.parent.mkdir(parents=True)
(oracle.parent/'check.hpp').write_bytes((root/'common/tests/check.hpp').read_bytes())
oracle.write_text('#include "check.hpp"\\nint value();\\nint main() { try { std::fprintf(stdout,"partial trace"); CHECK(value()==1); } catch(const std::exception& error) { std::fprintf(stderr,"%s\\\\n",error.what()); return 1; } return 0; }\\n')
(fixture/'.gitignore').write_text('build/\\n')
directory=fixture/'build/cmake/release'; native=directory/'component'; native.mkdir(parents=True)
windows=os.name=='nt'
compiler=os.environ['CXX'] if windows else str(build.CACHE/'tools/gcc-16.2.0/bin/g++')
archiver=str(pathlib.Path(compiler).with_name('lib.exe')) if windows else str(build.CACHE/'tools/gcc-16.2.0/bin/gcc-ar')
production=native/('value.obj' if windows else 'value.o'); test=native/('oracle.obj' if windows else 'oracle.o')
commands=[]
for path,obj in ((source,production),(oracle,test)):
    argv=[compiler,'/nologo','/std:c++20','/EHsc','/Od','/Z7','/I','../../../../common/tests','/Fo'+obj.name,'/c',str(path)] if windows else [compiler,'-std=c++20','-O0','-I','../../../../common/tests','-o',obj.name,'-c',str(path)]
    commands.append({'directory':str(native),'file':str(path),'arguments':argv})
(directory/'compile_commands.json').write_text(json.dumps(commands))
link=native/'CMakeFiles/value_test.dir'/('link.json' if windows else 'link.txt'); link.parent.mkdir(parents=True)
link.write_bytes(v.encode([compiler,'/nologo','/Fevalue_test.exe','oracle.obj','libvalue.lib']) if windows else (compiler+' -Wl,--dependency-file=CMakeFiles/value_test.dir/link.d -o value_test oracle.o libvalue.a').encode())
preparation=fixture/'build/preparation'; preparation.mkdir()
env=mutate.environment(fixture)
compiles=[]
for command,obj in zip(commands,(production,test)):
    argv=command['arguments'].copy()
    if windows: argv[next(index for index,arg in enumerate(argv) if arg.startswith('/Fo'))]='/Fo'+str(obj)
    else: argv[argv.index('-o')+1]=str(obj)
    argv[argv.index('/I' if windows else '-I')+1]=str(oracle.parent)
    compiles.append(argv)
archive=[archiver,'/nologo','/OUT:'+str(native/'libvalue.lib'),str(production)] if windows else [archiver,'rcs',str(native/'libvalue.a'),str(production)]
argvs=[['git','init','-q',str(fixture)],['git','-C',str(fixture),'add','.'],*compiles,archive]
for index,argv in enumerate(argvs):
    output=preparation/str(index); output.mkdir()
    record=v.execute({'id':'prepare','argv':argv,'environment':dict(env,TMPDIR=str(output/'tmp')),'timeout_s':60,'log_bytes':1024*1024},fixture,output,'windows-amd64' if windows else 'fixture')
    v.write_new(output/'record.json',record)
    assert record['exit_code']==0 and record['complete'] and record['cleanup'], record
    if index in (2,3): assert (production if index==2 else test).is_file(), record
manifest={'version':1,'engine':'cpp','scope':'One artificial native fixture; not production mutation evidence','mutations':[{'id':'value','file':'common/src/value.cpp','test':'value_test','oracle':'common/tests/value_test.cpp','before':'return 1;','after':'return 2;'}]}
if not windows:
    # Exercise the actual linker's response parsing without dropping any native flag.
    link.write_bytes(link.read_bytes()+b' -lm'*64)
output=fixture/'build/mutants'
assert mutate.cpp_run(manifest,directory,output,fixture)==0
result=v.decode(v.read(output/'result.json'))
assert result['planned']==result['killed']==1 and result['source_unchanged'] and not result['interrupted']
for name in ('baseline-value','value'):
    path=output/name
    assert (path/('program.exe' if windows else 'program')).is_file() and (path/'test').is_dir()
    if not windows:
        assert (path/'program.d').is_file() and not (link.parent/'link.d').exists()
    for phase in ('compile','link','test'):
        record=v.decode(v.read(path/phase/'record.json'))
        assert record['complete'] and record['cleanup']
        v.schema(record,'evidence',('properties','checks','items'))
        plan=v.decode(v.read(path/phase/'plan.json'))
        assert plan['argv']==record['argv'] and plan['log_bytes']==32*1024**2
        if phase=='link' and not windows:
            arguments=v.decode(v.read(path/phase/'arguments.json'))
            response=path/phase/'arguments.rsp'
            import shlex
            assert len(arguments)>64 and shlex.split(response.read_text())==arguments[1:]
            assert arguments.count('-lm')==64 and record['argv']==[arguments[0],'@'+str(response)]
# Identical native targets share one frozen baseline; successfully drained artifacts can be removed without losing original facts.
grouped=json.loads(json.dumps(manifest))
grouped['mutations'].append(dict(grouped['mutations'][0],id='other',after='return 3;'))
pruned=fixture/'build/mutants-pruned'
assert mutate.cpp_run(grouped,directory,pruned,fixture,prune=True)==0
summary=v.decode(v.read(pruned/'result.json'))
assert summary['planned']==summary['killed']==2 and summary['baselines']=={'value':'baseline-value','other':'baseline-value'}
assert len(summary['checks'])==3 and not(pruned/'baseline-other').exists()
for name in ('baseline-value','value','other'):
    path=pruned/name
    removed=v.decode(v.read(path/'pruned.json'))
    assert removed['owned_process_cleanup'] and len(removed['files'])==2
    for artifact in removed['files']:
        assert not(path/artifact['path']).exists() and artifact['bytes']>0
        phase='compile' if artifact['path'].endswith(('.o','.obj')) else 'link'
        assert artifact==v.decode(v.read(path/(phase+'-artifact.json')))
    for phase in ('compile','link','test'):
        record=v.decode(v.read(path/phase/'record.json'))
        assert record['complete'] and record['cleanup'] and record['termination']=='exited'
        v.schema(record,'evidence',('properties','checks','items'))
# A surviving mutant keeps its actual binary and stops this storage-bounded campaign before later mutations execute.
surviving=json.loads(json.dumps(manifest))
surviving['mutations'].extend([dict(surviving['mutations'][0],id='survivor',after='return (1);'),dict(surviving['mutations'][0],id='later',after='return 4;')])
blocked=fixture/'build/mutants-surviving'
assert mutate.cpp_run(surviving,directory,blocked,fixture,prune=True)==2
summary=v.decode(v.read(blocked/'result.json'))
assert summary['status']=='blocked' and summary['planned']==3 and summary['killed']==1 and len(summary['checks'])==3
assert (blocked/'survivor'/('program.exe' if windows else 'program')).is_file()
assert not(blocked/'survivor/pruned.json').exists() and not(blocked/'later').exists()
# Build metadata is part of baseline identity, even though Git correctly ignores generated build directories.
original_recipe=mutate.cpp_recipe
commands_file=directory/'compile_commands.json';original_commands=commands_file.read_bytes()
def altered(*args):
    result=original_recipe(*args)
    commands_file.write_bytes(commands_file.read_bytes()+b' ')
    return result
mutate.cpp_recipe=altered
changed=fixture/'build/mutants-recipe-drift'
assert mutate.cpp_run(manifest,directory,changed,fixture,prune=True)==2
summary=v.decode(v.read(changed/'result.json'))
assert summary['status']=='blocked' and summary['killed']==0 and summary['checks'][0]['status']=='invalid'
assert not(changed/'baseline-value/compile').exists()
mutate.cpp_recipe=original_recipe;commands_file.write_bytes(original_commands)
# Missing and ambiguous target recipes must fail before any compiler or test child is started.
saved_link=link.read_bytes()
for ambiguous in (False,True):
    duplicate=link.with_suffix('.txt' if windows else '.json')
    if ambiguous: duplicate.write_bytes(b'[]')
    else: link.unlink()
    try:
        mutate.cpp_run(manifest,directory,fixture/('build/ambiguous-link' if ambiguous else 'build/missing-link'),fixture)
    except v.Invalid as error:
        assert 'mutation-link-recipe' in str(error)
    else:
        raise AssertionError('unbound native link recipe accepted')
    if ambiguous: duplicate.unlink()
    else: link.write_bytes(saved_link)
if not windows: assert v.owned_members()==[]
print('CPP-FIXTURE '+json.dumps(result))
"""
        with tempfile.TemporaryDirectory(dir=temporary) as directory:
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(root), directory], cwd=root, env=self.environment(), capture_output=True, timeout=300
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            rows = [line.removeprefix("CPP-FIXTURE ") for line in result.stdout.decode().splitlines() if line.startswith("CPP-FIXTURE ")]
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0])["status"], "passed")

    @unittest.skipUnless(platform.system() in {"Linux", "Windows"}, "Existing offline native Go compiler")
    def test_package_discovery(self) -> None:
        """Actual Go discovery ignores saved evidence while its overlay still changes the tested code."""
        root = Path(__file__).resolve().parents[1]
        temporary = root / "build/mutation-fixtures"
        temporary.mkdir(parents=True, exist_ok=True)
        script = """
import base64,ctypes,json,os,pathlib,shutil,sys
from tools import build,mutate,verify as v
if os.name!='nt': assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
root=pathlib.Path(sys.argv[1]); fixture=pathlib.Path(sys.argv[2])
(fixture/'go.mod').write_text('module example\\n\\ngo 1.27\\n')
(fixture/'value.go').write_text('package example\\nfunc Value() int { return 1 }\\n')
(fixture/'value_test.go').write_text('package example\\nimport "testing"\\nfunc TestValue(t *testing.T) { if Value()!=1 { t.Fatal("changed value") } }\\n')
output=fixture/'build/evidence'; output.mkdir(parents=True)
item={'id':'value','file':'value.go','replacement':'package example\\nfunc Value() int { return 2 }\\n'}
mapping=mutate.overlay(output,item,fixture)
env=mutate.environment(fixture)
go=shutil.which('go') if os.name=='nt' else str(build.CACHE/'tools/go-1.27.2/bin/go')
assert go is not None
def run(name,args):
    directory=fixture/'build'/name; directory.mkdir()
    record=v.execute({'id':name,'argv':[go,'-C',str(fixture),*args],'environment':dict(env,TMPDIR=str(directory/'tmp')),'timeout_s':90,'log_bytes':1024*1024},root,directory,'windows-amd64' if os.name=='nt' else 'fixture')
    assert record['complete'] and record['cleanup']
    return record,v.read(directory/record['stdout']['path'])
record,version=run('version',['version'])
assert record['exit_code']==0 and version.startswith(b'go version go1.27.2 ')
record,normal=run('list',['list','./...'])
assert record['exit_code']==0 and normal.splitlines()==[b'example']
record,data=run('overlay',['test','-json','-count=1','-overlay='+str(mapping),'-run=^TestValue$','.'])
outcome=mutate.outcome(record,data,'example','TestValue')
if outcome!='killed':
    # Keep the exact native failure before the enclosing fixture retires its temporary paths.
    diagnostics=v.read(fixture/'build/overlay'/record['stderr']['path'])
    print('MUTATION-FIXTURE '+json.dumps({'record':record,'outcome':outcome,'stdout':base64.b64encode(data).decode(),'stderr':base64.b64encode(diagnostics).decode()}),file=sys.stderr,flush=True)
assert outcome=='killed'
legacy=output/'legacy.go'; legacy.write_text(item['replacement'])
record,old=run('legacy',['list','./...'])
assert record['exit_code']==0 and old.splitlines()!=normal.splitlines()
if os.name!='nt': assert v.owned_members()==[]
print(json.dumps({'saved_overlay_works':True,'new_packages':normal.decode().splitlines(),'legacy_packages':old.decode().splitlines()}))
"""
        with tempfile.TemporaryDirectory(dir=temporary) as directory:
            result = subprocess.run([sys.executable, "-B", "-c", script, str(root), directory], cwd=root, capture_output=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertTrue(json.loads(result.stdout)["saved_overlay_works"])

    def test_native_outcomes(self) -> None:
        """Only the planned, executed test can kill a mutant."""
        record = {"complete": True, "cleanup": True, "termination": "exited", "exit_code": 1}

        def stream(actions: list[tuple[str, str | None]]) -> bytes:
            """Create synthetic Go events; these fixtures are not production mutation evidence."""
            return b"\n".join(json.dumps({"Package": "example", "Action": action, **({"Test": test} if test else {})}).encode() for action, test in actions)

        failed = stream([("run", "TestCase"), ("fail", "TestCase"), ("fail", None)])
        self.assertEqual(mutate.outcome(record, failed, "example", "TestCase"), "killed")
        for text in ("panic: index out of range", "fatal error: runtime", "test timed out after 30s", "WARNING: DATA RACE"):
            diagnostic = json.dumps({"Package": "example", "Action": "output", "Test": "TestCase", "Output": text}).encode()
            self.assertEqual(mutate.outcome(record, diagnostic + b"\n" + failed, "example", "TestCase"), "invalid")
        for actions in [
            [],
            [("fail", None)],
            [("run", "TestOther"), ("fail", "TestOther"), ("fail", None)],
            [("run", "TestCase"), ("skip", "TestCase"), ("pass", None)],
            [("run", "TestCase"), ("fail", "TestCase")],
        ]:
            self.assertEqual(mutate.outcome(record, stream(actions), "example", "TestCase"), "invalid")
        for field, value in [("complete", False), ("cleanup", False), ("termination", "timeout")]:
            self.assertEqual(mutate.outcome({**record, field: value}, failed, "example", "TestCase"), "invalid")
        passed = stream([("run", "TestCase"), ("pass", "TestCase"), ("pass", None)])
        record["exit_code"] = 0
        self.assertEqual(mutate.outcome(record, passed, "example", "TestCase"), "survived")
        self.assertEqual(mutate.outcome(record, passed, "example", "TestCase", True), "passed")
        self.assertEqual(mutate.outcome(record, b"truncated", "example", "TestCase"), "invalid")
        for value in (b"[]", b"null", b"1", b'"pass"'):
            self.assertEqual(mutate.outcome(record, value, "example", "TestCase"), "invalid")

    def test_plan(self) -> None:
        """Freeze the finite denominator and refuse stale, duplicate, or test-only edits."""
        root = Path(__file__).resolve().parents[1]
        manifest = verify.decode(verify.read(root / "tests/mutations.json"))
        expected = {
            "skip-version",
            "advance-retry",
            "drop-history",
            "keep-extra-history",
            "omit-delete",
            "ignore-write-error",
            "accept-poisoned-write",
            "misclassify-begin",
            "unfreeze-rollback",
            "unfreeze-commit",
            "accept-failed-commit",
            "commit-on-panic",
            "accept-invalid-record",
            "accept-history-tail",
            "accept-orphan",
            "accept-corrupt-open",
            "publish-partial-snapshot",
            "publish-partial-history",
            "ignore-pinned-reader",
            "accept-connection-drift",
            "ignore-metadata-read",
            "ignore-record-size",
            "ignore-retry-query",
            "ignore-retained-scan",
            "retain-step-error",
            "retain-close-error",
            "created-close-error",
            "directory-sync-error",
            "directory-close-error",
            "open-error-class",
        }
        planned = mutate.plan(manifest, root)
        self.assertEqual(len(planned), len(expected))
        self.assertEqual({item["id"] for item in planned}, expected)
        for field, value in [("before", "absent anchor"), ("file", "../commit.go"), ("file", "polaris/internal/storage/model_test.go"), ("test", "Test.*")]:
            changed = copy.deepcopy(manifest)
            changed["mutations"][0][field] = value
            with self.assertRaises(verify.Invalid):
                mutate.plan(changed, root)
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            package = isolated / "example"
            package.mkdir()
            source = package / "value.go"
            source.write_text("package example\nfunc Value() int { return 1 }\n", encoding="utf-8")
            oracle = isolated / "oracle.go.in"
            oracle.write_text("package example\n", encoding="utf-8")
            value = {
                "version": 1,
                "scope": "Added test fixtures may not replace a production or preexisting test file.",
                "package": "./example",
                "import": "example",
                "fixtures": [{"source": "oracle.go.in", "target": "example/oracle_test.go"}],
                "mutations": [{"id": "value", "file": "example/value.go", "test": "TestValue", "before": "return 1", "after": "return 2"}],
            }
            item = mutate.plan(value, isolated)[0]
            oracles = mutate.fixtures(value, isolated)
            output = isolated / "output"
            output.mkdir()
            baseline = mutate.overlay(output, None, isolated, oracles=oracles, name="baseline-TestValue")
            replacement = mutate.overlay(output, item, isolated, oracles=oracles)
            first, second = (verify.decode(path.read_bytes())["Replace"] for path in (baseline, replacement))
            target = str(package / "oracle_test.go")
            self.assertEqual(first[target], second[target])
            self.assertEqual(Path(first[target]).read_bytes(), oracle.read_bytes())
            self.assertEqual(set(first), {target})
            self.assertEqual(set(second), {target, str(source)})
            self.assertEqual(source.read_text(encoding="utf-8"), "package example\nfunc Value() int { return 1 }\n")
            for field, replacement in [
                ("source", "example/value.go"),
                ("source", "missing.go.in"),
                ("source", "../escape.go.in"),
                ("target", "example/value.go"),
                ("target", "other/oracle_test.go"),
                ("target", "../oracle_test.go"),
                ("target", "example/oracle.go"),
            ]:
                changed = copy.deepcopy(value)
                changed["fixtures"][0][field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(verify.Invalid):
                    mutate.plan(changed, isolated)
            changed = copy.deepcopy(value)
            changed["fixtures"].append(changed["fixtures"][0])
            with self.assertRaises(verify.Invalid):
                mutate.plan(changed, isolated)
            (package / "oracle_test.go").write_text("package example\n", encoding="utf-8")
            with self.assertRaises(verify.Invalid):
                mutate.plan(value, isolated)
            Path(first[target]).write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(verify.Invalid, "mutation-fixture-changed"):
                mutate.overlay(output, item, isolated, oracles=oracles)
        manifest["mutations"].append(manifest["mutations"][0])
        with self.assertRaises(verify.Invalid):
            mutate.plan(manifest, root)

        # Keep the executed state/fault and validator operators intact when composing whole-rule evidence.
        semantic = verify.decode(verify.read(root / "tests/mutations.json"))["mutations"]
        validators = verify.decode(verify.read(root / "polaris/internal/storage/mutations.json"))["mutations"]
        core = verify.decode(verify.read(root / "polaris/internal/storage/core-mutations.json"))
        self.assertEqual(core["mutations"][: len(semantic)], semantic)
        self.assertEqual(core["mutations"][len(semantic) : len(semantic) + len(validators)], validators)
        self.assertEqual((len(semantic), len(validators), len(core["mutations"])), (30, 39, 99))
        planned = mutate.plan(core, root)
        self.assertEqual(len(planned), 99)
        self.assertEqual(len({item["id"] for item in planned}), 99)
        maintenance = verify.decode(verify.read(root / "polaris/internal/storage/maintenance-mutations.json"))
        version = verify.decode(verify.read(root / "polaris/internal/storage/version-mutations.json"))
        self.assertEqual(len(mutate.plan(maintenance, root)), 7)
        self.assertEqual(len(mutate.plan(version, root)), 1)
        self.assertEqual(version["mutations"], [{**next(item for item in core["mutations"] if item["id"] == "version-size"), "test": "TestVersionBoundary"}])
        self.assertEqual(len({item["id"] for item in planned + mutate.plan(maintenance, root) + mutate.plan(version, root)}), 106)
        self.assertEqual(
            {Path(item["file"]).name for item in planned},
            {"batch.go", "commit.go", "feed.go", "lock_linux.go", "model.go", "read.go", "schema.go", "store.go"},
        )
        config, _, _ = verify.configuration(root / "development.json", root)
        check = next(item for item in config["checks"] if item["id"] == "storage-core-mutants")
        examples = next(item for item in config["checks"] if item["id"] == "storage-examples")
        self.assertEqual(check["argv"][2:5], ["tools/observe.py", "python", "tests.test_sensitivity.SensitivityTests.test_current"])
        self.assertEqual(check["adapter"], "observed-cases")
        self.assertEqual(
            check["probes"], [{"contract": "STORAGE-ASSURANCE", "minimum_hits": 106, "test": "tests.test_sensitivity.SensitivityTests.test_current"}]
        )
        self.assertLessEqual({item["test"] for item in planned}, set(examples["expected_tests"]))
        component = next(item for item in config["components"] if item["id"] == "polaris-storage")
        required = next(item for item in component["requirements"] if item["rule"] == "DEV-COVERAGE" and item["scenario"] == "mutation")
        numeric = next(item for item in component["requirements"] if item.get("checks") == ["storage-numeric-mutants"])
        self.assertEqual(required["checks"], [check["id"]])
        self.assertEqual(required["requires"], [{key: numeric[key] for key in ("contract", "rule", "scenario")}])

    def test_cpp_outcomes(self) -> None:
        """Require the unchanged oracle's real assertion location and a normal terminal event, even for zero prior hits."""
        with tempfile.TemporaryDirectory() as directory:
            oracle = Path(directory) / "model_test.cpp"
            oracle.write_text("// Independent oracle\nCHECK(actual == expected);\n", encoding="utf-8")
            record = {"complete": True, "cleanup": True, "termination": "exited", "exit_code": 1}
            marker = b'ASTRA-CHECKS {"hits":0}\n'
            failure = (str(oracle) + ":2: actual == expected\n").encode()
            self.assertEqual(mutate.cpp_outcome(record, marker, failure, oracle), "killed")
            self.assertEqual(mutate.cpp_outcome(record, b"partial trace\n" + marker, failure, oracle), "killed")
            for field, value in [
                ("complete", False),
                ("cleanup", False),
                ("termination", "timeout"),
                ("termination", "log-limit"),
                ("exit_code", -11),
                ("exit_code", 2),
            ]:
                self.assertEqual(mutate.cpp_outcome({**record, field: value}, marker, failure, oracle), "invalid")
            for stdout, stderr in [
                (b"", failure),
                (marker * 2, failure),
                (b"partial trace" + marker, failure),
                (b'ASTRA-CHECKS {"hits":true}\n', failure),
                (marker, b"compiler error"),
                (marker, (str(oracle) + ":1: failed\n").encode()),
                (marker, (str(oracle) + ":99: failed\n").encode()),
            ]:
                self.assertEqual(mutate.cpp_outcome(record, stdout, stderr, oracle), "invalid")
            passed = {**record, "exit_code": 0}
            self.assertEqual(mutate.cpp_outcome(passed, b'ASTRA-CHECKS {"hits":1}\n', b"", oracle), "survived")
            self.assertEqual(mutate.cpp_outcome(passed, b'ASTRA-CHECKS {"hits":1}\n', b"", oracle, True), "passed")
            self.assertEqual(mutate.cpp_outcome(passed, marker, b"", oracle), "invalid")

    def test_cpp_plan(self) -> None:
        """The committed exact-anchor C++ denominator cannot edit tests, lose an oracle or contain stale replacements."""
        root = Path(__file__).resolve().parents[1]
        manifest = verify.decode(verify.read(root / "tests/cpp-mutations.json"))
        self.assertEqual(len(mutate.cpp_plan(manifest, root)), 34)
        for field, value in [
            ("file", "common/tests/store_model_test.cpp"),
            ("oracle", "common/src/store.cpp"),
            ("test", "star_.*_test"),
            ("before", "absent anchor"),
        ]:
            changed = copy.deepcopy(manifest)
            changed["mutations"][0][field] = value
            with self.assertRaises(verify.Invalid):
                mutate.cpp_plan(changed, root)
        manifest["mutations"].append(manifest["mutations"][0])
        with self.assertRaises(verify.Invalid):
            mutate.cpp_plan(manifest, root)

    def test_cpp_recipe(self) -> None:
        """Only the frozen production compile input and output change; link inputs retain the independent oracle object."""
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build/cmake/release"
            build.mkdir(parents=True)
            source = root / "common/src/value.cpp"
            oracle = root / "common/tests/value_test.cpp"
            source.parent.mkdir(parents=True)
            oracle.parent.mkdir(parents=True)
            source.write_text("int value() { return 1; }\n", encoding="utf-8")
            oracle.write_text("CHECK(value() == 1);\n", encoding="utf-8")
            compiler = root / "cache/tools/gcc-16.2.0/bin/g++"
            test_object = build / "CMakeFiles/example_test.dir/value_test.cpp.o"
            test_object.parent.mkdir(parents=True)
            test_object.write_bytes(b"original test object")
            library = build / "libcore.a"
            library.write_bytes(b"original production archive")
            commands = [
                {"directory": str(build), "file": str(source), "arguments": [str(compiler), "-DNAME=a b", "-o", "value.cpp.o", "-c", str(source)]},
                {"directory": str(build), "file": str(oracle), "arguments": [str(compiler), "-o", str(test_object), "-c", str(oracle)]},
            ]
            (build / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")
            (test_object.parent / "link.txt").write_text(
                f'"{compiler}" -Wl,--dependency-file=CMakeFiles/example_test.dir/link.d -o example_test "{test_object.relative_to(build)}" "{library.relative_to(build)}"',
                encoding="utf-8",
            )
            item = {"id": "case", "file": "common/src/value.cpp", "oracle": "common/tests/value_test.cpp", "test": "example_test"}
            replacement, object_file, executable = (root / "build" / name for name in ("mutant.cpp", "mutant.o", "mutant-test"))
            with patch.object(mutate.build, "CACHE", root / "cache"):
                compile, link, inputs = mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                self.assertEqual(compile[1], "-DNAME=a b")
                self.assertEqual(compile[compile.index("-c") + 1], str(replacement))
                self.assertEqual(compile[compile.index("-o") + 1], str(object_file))
                self.assertEqual(compile[-2:], ["-iquote", str(source.parent)])
                self.assertEqual(link[1], str(object_file))
                self.assertEqual(link[link.index("-o") + 1], str(executable))
                self.assertIn("-Wl,--dependency-file=" + str(executable.with_suffix(".d")), link)
                self.assertIn(str(test_object), link)
                self.assertIn(str(library), link)
                self.assertEqual(inputs[str(test_object)], verify.file_digest(test_object))
                self.assertEqual(inputs[str(library)], verify.file_digest(library))
                nested = build / "component"
                nested.mkdir()
                commands[0]["directory"] = commands[1]["directory"] = str(nested)
                commands[0]["arguments"][1:1] = ["-I", "../include", "-iquote../quoted"]
                # A relative oracle output must be interpreted from its own nested working directory.
                commands[1]["arguments"][2] = "../" + str(test_object.relative_to(build))
                (build / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")
                compile, _, _ = mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                self.assertIn(str(build / "include"), compile)
                self.assertIn("-iquote" + str(build / "quoted"), compile)
                for index in (0, 1):
                    changed = copy.deepcopy(commands)
                    changed[index]["directory"] = str(root)
                    (build / "compile_commands.json").write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaises(verify.Invalid):
                        mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                changed = copy.deepcopy(commands)
                changed[0]["arguments"].insert(1, "@flags.rsp")
                (build / "compile_commands.json").write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(verify.Invalid):
                    mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                (build / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")
                for changed in [{**item, "test": "absent_test"}, {**item, "file": "common/src/other.cpp"}]:
                    with self.assertRaises((verify.Invalid, FileNotFoundError)):
                        mutate.cpp_recipe(build, changed, root, replacement, object_file, executable)

            # Structured Windows recipes are syntax/oracle controls here; fake object bytes are never executed as mutation evidence.
            object_file, executable = root / "build/mutant.obj", root / "build/mutant-test.exe"
            compiler = root / "cache/cl.exe"
            compiler.parent.mkdir(parents=True, exist_ok=True)
            compiler.write_bytes(b"synthetic compiler identity")
            test_object = build / "CMakeFiles/example_test.dir/oracle.obj"
            test_object.write_bytes(b"unchanged oracle object")
            library = build / "core.lib"
            library.write_bytes(b"unchanged production archive")
            commands = [
                {
                    "directory": str(build),
                    "file": str(path),
                    "arguments": [str(compiler), "/nologo", "/std:c++20", "/EHsc", "/Z7", "/DNAME=a b", "/I", "include", "/Fo" + obj, "/c", str(path)],
                }
                for path, obj in ((source, "value.obj"), (oracle, str(test_object.relative_to(build))))
            ]
            link = [str(compiler), "/nologo", "/Feexample_test.exe", str(test_object.relative_to(build)), str(library.relative_to(build))]
            link_path = test_object.parent / "link.json"
            (build / "compile_commands.json").write_bytes(verify.encode(commands))
            link_path.write_bytes(verify.encode(link))
            with patch.dict(os.environ, {"CXX": str(compiler)}):
                compile, linked, inputs = mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                self.assertEqual(compile[compile.index("/c") + 1], str(replacement))
                self.assertIn("/Fo" + str(object_file), compile)
                self.assertEqual(compile[compile.index("/I") + 1], str(build / "include"))
                self.assertIn("/DNAME=a b", compile)
                self.assertEqual(linked[1], str(object_file))
                self.assertIn("/Fe" + str(executable), linked)
                self.assertEqual(inputs, {str(test_object): verify.file_digest(test_object), str(library): verify.file_digest(library)})
                for flag in ("/Zi", "/Fdoutside.pdb", "/Ycpch.hpp", "/ifcOutputoutside", "/analyze:logoutside", "@flags.rsp"):
                    changed = copy.deepcopy(commands)
                    changed[0]["arguments"].insert(1, flag)
                    (build / "compile_commands.json").write_bytes(verify.encode(changed))
                    with self.subTest(flag=flag), self.assertRaisesRegex(verify.Invalid, "mutation-recipe-side-output"):
                        mutate.cpp_recipe(build, item, root, replacement, object_file, executable)
                (build / "compile_commands.json").write_bytes(verify.encode(commands))
                for changed in (link[:-2] + [str(library)], link + ["@link.rsp"], link + ["/PDB:outside.pdb"], link + [str(source)]):
                    link_path.write_bytes(verify.encode(changed))
                    with self.assertRaises(verify.Invalid):
                        mutate.cpp_recipe(build, item, root, replacement, object_file, executable)


if __name__ == "__main__":
    unittest.main()
