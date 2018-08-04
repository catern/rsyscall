let pkgs = import <nixpkgs> {}; in
with pkgs.python36Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [ mypy ];
  propagatedBuildInputs = [ (import ../c)
      trio cffi dataclasses pkgconfig python-prctl pkgs.nginx ];
}

