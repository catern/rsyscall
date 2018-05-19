with import <nixpkgs> {};

let
python = python3.withPackages (ps: [ps.supervise_api]);
in
stdenv.mkDerivation {
  name = "rsyscall";
  src = ./.;
  propogatedBuildInputs = [ python ];
  buildInputs = [ autoreconfHook autoconf automake libtool pkgconfig ];
}
