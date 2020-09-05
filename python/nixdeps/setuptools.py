"""A setuptools entrypoint to store dependencies on Nix packages at build-time

setuptools automatically registers this entry-point when you have the
nixdeps module on your PYTHONPATH. Then you can provide the following
keyword argument to `setup`:
```
nix_deps = {'mypkg._whatever': ['hello', 'goodbye']}
```
and then, if you have dependencies on the 'hello' and 'goodbye' Nix
packages, after a setuptools build, you will be able to use:
```
import_nixdep('mypkgs._whatever', 'hello')
import_nixdep('mypkgs._whatever', 'goodbye')
```

BUG: Note that we currently require you depend on packages by
explicitly setting environment variables containing the paths of those
packages. This can be done by, e.g.:
```
buildPythonPackage {
  hello = pkgs.hello;
  goodbye = pkgs.goodbye;
  ...
}
```
Merely having your dependencies in buildInputs will not work,
i.e. this is not sufficient:
```
buildPythonPackage {
  buildInputs = [ pkgs.hello pkgs.goodbye ];
}
```
This will be fixed later, so all you have to do is have the packages
in buildInputs; this means propagatedBuildInputs etc. will also work.

"""
import setuptools
import functools
import os
import os.path
import json
import typing as t
from pathlib import Path
from distutils import log
import subprocess

__all__ = [
    'nix_deps',
]

def write_json(output_path: Path, path: str, closure: t.List[str]) -> None:
    with open(output_path, 'w') as f:
        json.dump({
            "path": path,
            "closure": closure,
        }, f, indent=2)

def write_init(output: Path) -> None:
    with output.open('w') as f:
        pass

def get_dep_with_nix_store(dep: str) -> t.Tuple[str, t.List[str]]:
    if dep not in os.environ:
        raise Exception("couldn't find dep", dep, "in environment")
    path = os.environ[dep]
    # use nix-store to dump the closure
    closure_text = subprocess.run(["nix-store", "--query", "--requisites", path],
                                  capture_output=True, check=True).stdout
    closure = [line.decode() for line in closure_text.split()]
    return path, closure

def parse_references_graph(lines: t.List[str]) -> t.Dict[str, t.List[str]]:
    it = iter(lines)
    ret: t.Dict[str, t.List[str]] = {}
    while True:
        try:
            path = next(it)
        except StopIteration:
            return ret
        number = int(next(it))
        refs = [next(it) for _ in range(number)]
        ret[path] = refs

def closure_of(path: str, refs: t.Dict[str, t.List[str]]) -> t.Set[str]:
    return frozenset().union(*[
        {path} if ref == path else closure_of(ref, refs)
        for ref in refs[path]])

def get_dep_from_exported_graph(nix_build_top: Path, dep: str) -> t.Tuple[str, t.List[str]]:
    # we're in a real build, use output of exportReferencesGraph
    closure_path = nix_build_top/dep
    with open(closure_path, 'r') as f:
        raw_db = f.read()
    lines = raw_db.split()
    path = lines[0]
    refs = parse_references_graph(lines)
    return path, list(closure_of(path, refs))

def get_fake_dep(dep: str) -> t.Tuple[str, t.List[str]]:
    # just fake it
    log.info("making up fake dep for %s" % dep)
    return "/dev/null/" + dep, ["/dev/null/" + dep + "/closure"]

def build_deps_module(self, output_dir: Path, deps: t.List[str]) -> None:
    "Write out to `output_dir` the .json files containing the specification for `deps`"
    nix_build_top = os.environ.get('NIX_BUILD_TOP')
    if 'IN_NIX_SHELL' in os.environ:
        get_dep = get_dep_with_nix_store
    elif nix_build_top:
        get_dep = functools.partial(get_dep_from_exported_graph, Path(nix_build_top))
    else:
        get_dep = get_fake_dep
    log.info("generating Nix deps module in %s" % output_dir)
    self.mkpath(str(output_dir))
    self.execute(write_init, [output_dir/"__init__.py"])
    for dep in deps:
        log.info("writing Nix dep %s" % dep)
        path, closure = get_dep(dep)
        self.execute(write_json, [output_dir/(dep + '.json'), path, closure])

def add_deps_module(dist, module_name: str, deps: t.List[str]) -> None:
    # This function is heavily cribbed from cffi's setuptools_ext.py
    from setuptools.command.build_py import build_py
    from setuptools.command.build_ext import build_ext

    dist.package_data[module_name] = ['*.json']

    def generate_mod(self, outdir: str) -> None:
        build_deps_module(self, Path(outdir), deps)

    base_class = dist.cmdclass.get('build_py', build_py)
    class build_py_make_mod(base_class):
        def run(self):
            base_class.run(self)
            module_path = module_name.split('.')
            output_path = os.path.join(self.build_lib, *module_path)
            generate_mod(self, output_path)
    dist.cmdclass['build_py'] = build_py_make_mod

    # distutils and setuptools have no notion I could find of a
    # generated python module.  If we don't add module_name to
    # dist.py_modules, then things mostly work but there are some
    # combination of options (--root and --record) that will miss
    # the module.  So we add it here, which gives a few apparently
    # harmless warnings about not finding the file outside the
    # build directory.
    if dist.py_modules is None:
        dist.py_modules = []
    dist.py_modules.append(module_name)

    # the following is only for "build_ext -i"
    base_class_2 = dist.cmdclass.get('build_ext', build_ext)
    class build_ext_make_mod(base_class_2):
        def run(self):
            base_class_2.run(self)
            if self.inplace:
                build_py = self.get_finalized_command('build_py')
                output_path = build_py.get_package_dir(module_name)
                generate_mod(self, output_path)
    dist.cmdclass['build_ext'] = build_ext_make_mod

def nix_deps(dist, attr: str, value) -> None:
    "The main setuptools entry point. Automatically registered with setuptools via distutils.setup_keywords"
    assert attr == 'nix_deps'
    for module_name, deps in value.items():
        add_deps_module(dist, module_name, deps)
