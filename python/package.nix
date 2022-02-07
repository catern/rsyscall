{ pythonPackages
, librsyscall
, nix
, socat
, pkg-config
, openssh
, coreutils
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
  checkPhase = ''
  cd $out
  pytest -k 'not test_ssh and not test_net and not test_nix and not test_pgid and not test_fuse'
  '';
  nativeBuildInputs = [
    pkg-config
    ipython
    (pdoc3.overridePythonAttrs (_: { doCheck = false; }))
  ];
  buildInputs = [
    cffi
    librsyscall
  ];
  propagatedBuildInputs = [
    trio
    typeguard
    pyroute2
    outcome
    nixdeps
  ];
  exportReferencesGraph = [
    "nix" nix
    "librsyscall" librsyscall
    "openssh" openssh
    "coreutils" coreutils
  ];
}

