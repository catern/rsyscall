let pkgs = import <nixpkgs> {}; in
with pkgs.python36Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [ mypy ];
  propagatedBuildInputs = [ (import ../c) supervise_api trio cffi pkgconfig sfork ];
}

