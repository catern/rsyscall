let
  pkgs = import ../pinned.nix;
  nix = pkgs.nixUnstable.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "nix";
      rev = "ea5510e0499fbd1e264349e86d35ec0078fe73f5";
      sha256 = "0lli1gwwcqbhhm1s6816l33m38irqz1fzjrxb1gjp873d2lddg10";
  };});
  # hydra = pkgs.hydra;
  # hydra = pkgs.hydra.overrideAttrs (_: { src = /home/sbaugh/.local/src/hydra; });
  hydra = pkgs.hydra.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "hydra";
      rev = "542e9555dbbde4f03e112dfc5eb3a58da61dff24";
      sha256 = "0clxyrc0fc7ki2lra4jg30xrpqjryc7406yg9g8gqp61ldgqk2h4";
  };});
in
with pkgs.python37Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  # doCheck = false;
  checkInputs = [
  (mypy.overrideAttrs (_: { src = /home/sbaugh/.local/src/mypy; }))
pytest ];
  buildInputs = [ pkgs.openssh nix ];
  propagatedBuildInputs = [ (import ../c)
      trio cffi pkgconfig python-prctl pkgs.nginx typeguard
      requests h11 pkgs.pkgconfig hydra
      pkgs.postgresql_11
  ];
}

