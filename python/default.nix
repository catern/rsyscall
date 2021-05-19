let
  pkgs = import ../pinned.nix;
  # nix = pkgs.nixUnstable.overrideAttrs (_: { src = pkgs.fetchFromGitHub {
  #     owner = "catern";
  #     repo = "nix";
  #     rev = "b287df11b5f0dd41821349def360139b79f3bc65";
  #     sha256 = "0q8bnvz80dbg83z1m0mmg9rp3rv8y873vh4q1l04wkyqmzzimnnf";
  # };});
  nix = pkgs.nix;
  # hydra = (pkgs.hydra.override { nix = nix; }).overrideAttrs (_: { src = /home/sbaugh/.local/src/hydra; });
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
  rsyscall = (import ../c);
in

with pkgs.python39Packages;
buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [
  pydocstyle
  mypy
  # (mypy.overrideAttrs (_: { src = /home/sbaugh/.local/src/mypy; }))
  typing-extensions
  pytest
  pkgs.socat
  ];
  # ssh tests don't work because the build user's login shell is /noshell :(
  # net tests don't work because /dev/net/tun doesn't exist
  # nix tests don't work because something about "error: creating directory '/nix/var': Permission denied"
  # test_pgid doesn't work because /proc/sys/kernel/ns_last_pid isn't available for some reason
  checkPhase = "pytest rsyscall -k 'not ssh and not test_net and not test_nix and not test_pgid'";
  nativeBuildInputs = [
      pkgs.pkg-config pkgs.openssh nix
      rsyscall
      (pdoc3.overridePythonAttrs (_: { doCheck = false; }))
  ];
  # not sure how to set up the deps. we use binaries and libraries from C
  # rsyscall at build time to run tests; and we also use them at runtime for our
  # actual functionality. so should rsyscall be in nativeBuildInputs or
  # buildInputs? strictDeps fails if it's in nativeBuildInputs...
  strictDeps = false;
  nativePropagatedBuildInputs = [
      pkgs.s6
      # miredo
      pkgs.postgresql_11
      pkgs.iproute
      # opensmtpd
      pkgs.dovecot
      # hydra
      pkgs.powerdns
      pkgs.bubblewrap
      pkgs.nginx
  ];
  buildInputs = [
      cffi
  ];
  propagatedBuildInputs = [
      trio typeguard
      h11
      dnspython
      pyroute2
      outcome
  ];
  miredo = pkgs.miredo;
  nix = nix;
  rsyscall = rsyscall;
  openssh = pkgs.openssh;
  bash = pkgs.bash;
  coreutils = pkgs.coreutils;
  hello = pkgs.hello;
  exportReferencesGraph = [
    "miredo" pkgs.miredo
    "nix" pkgs.nix
    "rsyscall" rsyscall
    "openssh" pkgs.openssh
    "bash" pkgs.bash
    "coreutils" pkgs.coreutils
    "hello" pkgs.hello
  ];
}

