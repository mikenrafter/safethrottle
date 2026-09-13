{
  description = "safethrottle — local TUN gateway with asymptotic per-domain outbound rate limits";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    lib = nixpkgs.lib;
    pkgs = import nixpkgs { inherit system; };

    gateway = pkgs.rustPlatform.buildRustPackage {
      pname = "safethrottle-gateway";
      version = "0.1.0";
      src = ./.;
      cargoLock.lockFile = ./Cargo.lock;
      doCheck = true;
      meta = with lib; {
        description = "Asymptotic domain rate-limit TUN gateway";
        mainProgram = "safethrottle-gateway";
        license = licenses.mit;
      };
    };
  in
  {
    packages.${system} = {
      gateway = gateway;
      default = gateway;
    };

    overlays.default = final: prev: {
      safethrottle-gateway = self.packages.${final.system}.gateway;
    };

    devShells.${system}.default = pkgs.mkShell {
      packages = with pkgs; [
        cargo
        rustc
        rust-analyzer
      ];
    };
  };
}
