{ stdenv
, autoreconfHook
, autoconf
, automake
, libtool
, pkgconfig
, glibc
}:

stdenv.mkDerivation {
  name = "rsyscall";
  src = ./.;
  # rsyscall needs to build some static bootstrap binaries; that requires its library be built
  # statically in addition to dynamically.
  # we'll install both static and dynamic libraries, which is fine.
  dontDisableStatic = true;
  buildInputs = [ autoreconfHook autoconf automake libtool pkgconfig glibc glibc.static ];
}
