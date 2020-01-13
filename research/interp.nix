let
  pkgs = import ./pinned.nix;
  rsyscall = import ./python/default.nix;
in
pkgs.python37.withPackages (ps: [ rsyscall ])
