let
  pkgs = import ../pinned.nix;
in
pkgs.python39Packages.nixdeps
