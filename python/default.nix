let pkgs = import <nixpkgs> {}; in
with pkgs.python36Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [ mypy ];
  propagatedBuildInputs = [ (import ../c) (import ../../supervise/python)
      trio cffi pkgconfig sfork python-prctl ];
}

