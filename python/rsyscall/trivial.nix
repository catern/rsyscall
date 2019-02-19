{ string }:
{ trivial = builtins.derivation {
    name = "trivial";
    system = "x86_64-linux";
    builder = "/bin/sh";
    args = ["-c" "echo ${string} > $out; exit 0"];
  };
}
