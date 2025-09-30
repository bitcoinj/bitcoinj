{
  description = "bitcoinj";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs = inputs @ { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forEachSystem = f: builtins.listToAttrs (map (system: {
        name = system;
        value = f system;
      }) systems);
    in {
      devShells = forEachSystem(system:
        let
        inherit (pkgs) stdenv;
        pkgs = import nixpkgs {
          inherit system;
        };
        jdk = pkgs.temurin-bin-25;
        in {
        default = pkgs.mkShell {
          packages = with pkgs ; [
                jdk                        # This JDK will be in PATH
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = jdk;            # Run Gradle with this JDK
                })
            ];
          shellHook = ''
            echo "Welcome to bitcoinj!"
          '';
        };
      });
  };
}
