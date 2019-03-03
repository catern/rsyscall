let
  pkgs = import ../pinned.nix;
  nix = pkgs.nixUnstable.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "nix";
      rev = "ea5510e0499fbd1e264349e86d35ec0078fe73f5";
      sha256 = "0lli1gwwcqbhhm1s6816l33m38irqz1fzjrxb1gjp873d2lddg10";
  };});
  # hydra = pkgs.hydra;
  hydra = pkgs.hydra.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "hydra";
      rev = "43c62206aba7fb74bc2a08ad707d34a55a88b0fd";
      sha256 = "0v5qr5gj2wrbnib09qhi9ys4x1wqkr6x44nww4cv5anjjfxaff72";
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
  ];
}

