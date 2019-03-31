let
  pkgs = import ../pinned.nix;
  nix = pkgs.nixUnstable.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "nix";
      rev = "b287df11b5f0dd41821349def360139b79f3bc65";
      sha256 = "0q8bnvz80dbg83z1m0mmg9rp3rv8y873vh4q1l04wkyqmzzimnnf";
  };});
  hydra = pkgs.hydra;
  # hydra = (pkgs.hydra.override { nix = nix; }).overrideAttrs (_: { src = /home/sbaugh/.local/src/hydra; });
  # hydra = pkgs.hydra.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
  #     owner = "catern";
  #     repo = "hydra";
  #     rev = "542e9555dbbde4f03e112dfc5eb3a58da61dff24";
  #     sha256 = "0clxyrc0fc7ki2lra4jg30xrpqjryc7406yg9g8gqp61ldgqk2h4";
  # };});
  opensmtpd = pkgs.opensmtpd;
  # opensmtpd = pkgs.opensmtpd.overrideAttrs (_: { src = /home/sbaugh/.local/src/OpenSMTPD; });
  miredo = pkgs.miredo;
  # miredo = pkgs.miredo.overrideAttrs (oldAttrs: {
  #   src = builtins.fetchGit /home/sbaugh/.local/src/miredo;
  #   preConfigure = "cp ${pkgs.gettext}/share/gettext/gettext.h include/gettext.h";
  #   buildInputs = oldAttrs.buildInputs ++ [ pkgs.autoreconfHook ];
  # });
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
      opensmtpd
      pkgs.dovecot
      pkgs.s6
      miredo
  ];
}

