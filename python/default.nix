let pkgs = import ../pinned.nix; in
with pkgs.python37Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  # doCheck = false;
  checkInputs = [
  (mypy.overrideAttrs (_: { src = /home/sbaugh/.local/src/mypy; }))
pytest ];
  buildInputs = [ pkgs.openssh ];
  propagatedBuildInputs = [ (import ../c)
      trio cffi pkgconfig python-prctl pkgs.nginx typeguard
  ];
}

