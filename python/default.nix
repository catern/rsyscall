let
  pkgs = import ../pinned.nix;
in
pkgs.python310Packages.rsyscall
