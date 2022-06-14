let
  pythonOverrides = final: prev: {
    rsyscall = final.callPackage ./python/package.nix { };
    nixdeps = final.callPackage ./nixdeps/package.nix { };
  };
in
self: super: {
  librsyscall = self.callPackage ./c/package.nix { };

  python38 = super.python38.override {
    packageOverrides = pythonOverrides;
  };
  python39 = super.python39.override {
    packageOverrides = pythonOverrides;
  };
  python310 = super.python310.override {
    packageOverrides = pythonOverrides;
  };

  python38Packages = self.python38.pkgs;
  python39Packages = self.python39.pkgs;
  python310Packages = self.python310.pkgs;
}
