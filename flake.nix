{
  description = "A very basic flake";

  inputs = { nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable"; };

  outputs = { self, nixpkgs }:

    let
      systems = [ "x86_64-linux" "aarch64-linux" "i686-linux" "x86_64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
      nixpkgsFor = forAllSystems (system:
        import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        });

    in
    {
      overlay = import ./overlay.nix;

      packages = forAllSystems (system: with (nixpkgsFor.${system}); {
        inherit librsyscall;
        rsyscall = python3Packages.rsyscall;
        python38-rsyscall = python38Packages.rsyscall;
        python39-rsyscall = python39Packages.rsyscall;
      });

      defaultPackage = forAllSystems (system: self.packages.${system}.rsyscall);
    };
}
