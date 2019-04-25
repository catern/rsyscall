let
  pkgs = import ../pinned.nix;
  nix = pkgs.nixUnstable.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
      owner = "catern";
      repo = "nix";
      rev = "b287df11b5f0dd41821349def360139b79f3bc65";
      sha256 = "0q8bnvz80dbg83z1m0mmg9rp3rv8y873vh4q1l04wkyqmzzimnnf";
  };});
  # hydra = pkgs.hydra;
  hydra = (pkgs.hydra.override { nix = nix; }).overrideAttrs (_: { src = /home/sbaugh/.local/src/hydra; });
  # hydra = pkgs.hydra.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
  #     owner = "catern";
  #     repo = "hydra";
  #     rev = "542e9555dbbde4f03e112dfc5eb3a58da61dff24";
  #     sha256 = "0clxyrc0fc7ki2lra4jg30xrpqjryc7406yg9g8gqp61ldgqk2h4";
  # };});
  # opensmtpd = pkgs.opensmtpd;
  opensmtpd = pkgs.opensmtpd.overrideAttrs (_: { src = /home/sbaugh/.local/src/OpenSMTPD; });
  # miredo = pkgs.miredo;
  miredo = pkgs.miredo.overrideAttrs (oldAttrs: {
    # src = builtins.fetchGit { url = /home/sbaugh/.local/src/miredo; ref = "HEAD"; };
    src = builtins.fetchGit /home/sbaugh/.local/src/miredo;
    preConfigure = "cp ${pkgs.gettext}/share/gettext/gettext.h include/gettext.h";
    buildInputs = oldAttrs.buildInputs ++ [ pkgs.autoreconfHook ];
  });
  dnspython = pkgs.python37Packages.dnspython.overrideAttrs (oldAttrs: rec {
    version = "1.16.0";
    src = pkgs.python37Packages.fetchPypi {
      pname = oldAttrs.pname;
      inherit version;
      extension = "zip";
      sha256 = "00cfamn97w2vhq3id87f10mjna8ag5yz5dw0cy5s0sa3ipiyii9n";
    };
  });
  rsyscall = (import ../c);
in
with pkgs.python37Packages;

buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  # doCheck = false;
  checkInputs = [
  (mypy.overrideAttrs (_: { src = /home/sbaugh/.local/src/mypy; }))
  typing-extensions
pytest ];
  buildInputs = [ pkgs.openssh nix ];
  propagatedBuildInputs = [ rsyscall
      trio cffi pkgconfig python-prctl pkgs.nginx typeguard
      dnspython
      requests h11 pkgs.pkgconfig hydra
      pkgs.postgresql_11
      opensmtpd
      pkgs.dovecot
      pkgs.s6
      miredo
      pyroute2
      pkgs.powerdns
      pkgs.bubblewrap
  ];
  miredo = miredo;
  nix = nix;
  rsyscall = rsyscall;
  openssh = pkgs.openssh;
  bash = pkgs.bash;
  coreutils = pkgs.coreutils;
  exportReferencesGraph = [
    "miredo" pkgs.miredo
    "nix" pkgs.nix
    "rsyscall" rsyscall
    "openssh" pkgs.openssh
    "bash" pkgs.bash
    "coreutils" pkgs.coreutils
  ];
}

