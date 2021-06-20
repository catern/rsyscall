self: super: {
  librsyscall = self.callPackage ./c/package.nix { };
  python38 = super.python38.override {
    packageOverrides = final: prev: {
      rsyscall = final.callPackage ./python/package.nix { };
    };
  };
  python39 = super.python39.override {
    packageOverrides = final: prev: {
      rsyscall = final.callPackage ./python/package.nix { };
    };
  };

  python38Packages = self.python38.pkgs;
  python39Packages = self.python39.pkgs;
}
