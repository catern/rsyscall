with import ../pinned.nix;

stdenv.mkDerivation {
  name = "rsyscall";
  src = ./.;
  buildInputs = [ autoreconfHook autoconf automake libtool pkgconfig];
}
