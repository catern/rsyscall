with import <nixpkgs> {};

let
myPython = python3.withPackages (ps: [(import ../../supervise/python)]);
in
stdenv.mkDerivation {
  name = "rsyscall";
  src = ./.;
  buildInputs = [ autoreconfHook autoconf automake libtool pkgconfig myPython (import ../../supervise/c)];
}
