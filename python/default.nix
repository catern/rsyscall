let pkgs = import <nixpkgs> {
  overlays = [(self: super: {
    python3 = super.python3.overrideAttrs (_: {separateDebugInfo = true;});
  })];};
in
with pkgs.python36Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [ mypy ];
  buildInputs = [ pkgs.python3.debug ];
  propagatedBuildInputs = [ (import ../c) supervise_api trio cffi pkgconfig ];
}

