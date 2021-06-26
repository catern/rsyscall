# Super stripped down version of nixpkgs compat
# https://github.com/edolstra/flake-compat/blob/master/default.nix

let
  lockFile = builtins.fromJSON (builtins.readFile ./flake.lock);
  fetchTree = info:
    if info.type == "github" then
      {
        outPath = builtins.fetchTarball "https://api.${info.host or "github.com"}/repos/${info.owner}/${info.repo}/tarball/${info.rev}";
        rev = info.rev;
        shortRev = builtins.substring 0 7 info.rev;
        lastModified = info.lastModified;
        narHash = info.narHash;
      }
    else
      throw "flake input has unsupported input type '${info.type}'";
in
import (fetchTree lockFile.nodes.nixpkgs.locked) {
  config = { };
  overlays = [ (import ./overlay.nix) ];
}
