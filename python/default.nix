let pkgs = import <nixpkgs> {}; in
with pkgs.python37Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  # doCheck = false;
  checkInputs = [ mypy pytest pkgs.openssl ];
  buildInputs = [ pkgs.openssh ];
  propagatedBuildInputs = [ (import ../c)
      trio cffi pkgconfig python-prctl pkgs.nginx ];
}

