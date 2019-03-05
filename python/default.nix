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
      rev = "0e80bb56ee5ff06a2961c5a452de2c60c7358b21";
      sha256 = "18ai29650p3i5gcrnp38mbszb5121b92bzz8qncfx78d2m4db0jr";
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

