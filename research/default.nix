{
  vm = (import <nixpkgs/nixos> { configuration = {
    virtualisation.graphics = false;
    services.mingetty.autologinUser = "root";
    users.users.root.initialHashedPassword = "";
  }; }).vm;
}

# SHARED_DIR=/home/sbaugh/.local/src/rsyscall ./result/bin/run-nixos-vm -kernel $(readlink -f arch/x86_64/boot/bzImage) -serial pty
