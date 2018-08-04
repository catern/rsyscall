with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "rsyscall";
  src = ./.;
  buildInputs = [ autoreconfHook autoconf automake libtool pkgconfig];
}
