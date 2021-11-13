{ pythonPackages
, librsyscall
, nix
, socat
, pkg-config
, s6
, miredo
, postgresql_11
, iproute
, openssh
, opensmtpd
, dovecot
, hydra
, powerdns
, bubblewrap
, nginx
, bash
, coreutils
, hello
}:

with pythonPackages;
buildPythonPackage {
  name = "rsyscall";
  src = ./.;
  checkInputs = [
    pydocstyle
    mypy
    typing-extensions
    pytest
    socat
  ];
  # ssh tests don't work because the build user's login shell is /noshell :(
  # net tests don't work because /dev/net/tun doesn't exist
  # nix tests don't work because something about "error: creating directory '/nix/var': Permission denied"
  # test_pgid doesn't work because /proc/sys/kernel/ns_last_pid isn't available for some reason
  # fuse tests don't work because /dev/fuse doesn't exist
  checkPhase = "pytest rsyscall -k 'not ssh and not test_net and not test_nix and not test_pgid and not test_fuse'";
  nativeBuildInputs = [
    pkg-config
    openssh
    nix
    librsyscall
    (pdoc3.overridePythonAttrs (_: { doCheck = false; }))
  ];
  # not sure how to set up the deps. we use binaries and libraries from C
  # rsyscall at build time to run tests; and we also use them at runtime for our
  # actual functionality. so should rsyscall be in nativeBuildInputs or
  # buildInputs? strictDeps fails if it's in nativeBuildInputs...
  strictDeps = false;
  nativePropagatedBuildInputs = [
    s6
    # miredo
    postgresql_11
    iproute
    # opensmtpd
    dovecot
    # hydra
    powerdns
    bubblewrap
    nginx
  ];
  buildInputs = [
    cffi
  ];
  propagatedBuildInputs = [
    trio
    typeguard
    h11
    dnspython
    pyroute2
    outcome
    nixdeps
  ];
  exportReferencesGraph = [
    "miredo" miredo
    "nix" nix
    "librsyscall" librsyscall
    "openssh" openssh
    "bash" bash
    "coreutils" coreutils
    "hello" hello
  ];
}

