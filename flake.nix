{
  description = "bitcoinj";

  # this allows derivations with `__noChroot = true` and allows us to work around limitations with gradle
  # see https://zimbatm.com/notes/nix-packaging-the-heretic-way
  nixConfig.sandbox = "relaxed";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    flake-parts,
    devshell,
    gitignore,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem = {
        config,
        inputs',
        pkgs,
        lib,
        system,
        ...
      }: let
        inherit (pkgs) stdenv;

        # pick our jdk and gradle versions
        jdk = pkgs.jdk21.override {
            # enabling JavaFX in the JDK allows `nix run .#wallettemplate`  to work correctly.
            # This is because the `bitcoinj-wallettemplate:installDist` Gradle task does
            # not set up the Module Path correctly for JavaFX to be loaded from a Maven JAR.
            enableJavaFX = true;
        };
        gradle = pkgs.gradle;

      in {
        # define a devshell
        devShells.default = inputs'.devshell.legacyPackages.mkShell {
          # setup some environment variables
          env = with lib;
            mkMerge [
              [
                # Configure nix to use nixpgks
                {
                  name = "NIX_PATH";
                  value = "nixpkgs=${toString pkgs.path}";
                }
              ]
              (mkIf stdenv.isLinux [
                {
                  name = "JAVA_HOME";
                  eval = "$DEVSHELL_DIR/lib/openjdk";
                }
              ])
              (mkIf stdenv.isDarwin [
                {
                  name = "JAVA_HOME";
                  # TODO: Fix this so it isn't hardcoded to "zulu".
                  # I think it should be computed from `jdk` somehow.
                  eval = "$DEVSHELL_DIR/zulu-17.jdk/Contents/Home";
                }
              ])
            ];

          # add package dependencies
          packages = with lib;
            mkMerge [
              [
                jdk
                gradle
              ]
            ];
        };

        # define flake output packages
        packages = let
          # useful for filtering src trees based on gitignore
          inherit (gitignore.lib) gitignoreSource;

          # common properties across the derivations
          version = "0.0.1";
          src = gitignoreSource ./.;
        in {
          # This package is an example of an escape hatch
          wallettool = stdenv.mkDerivation {
            pname = "wallettool";
            inherit version src;

            # Disable the Nix build sandbox for this specific build.
            # This means the build can freely talk to the Internet.
            __noChroot = true;

            nativeBuildInputs = [gradle pkgs.makeWrapper];

            buildPhase = ''
              export GRADLE_USER_HOME=$(mktemp -d)
              gradle --no-daemon bitcoinj-wallettool:installDist
            '';

            installPhase = ''
              mkdir -p $out/share/vanilla
              cp -r wallettool/build/install/wallet-tool/* $out/share/vanilla
              makeWrapper $out/share/vanilla/bin/wallet-tool $out/bin/wallet-tool \
                    --set JAVA_HOME ${jdk}
            '';

            meta.mainProgram = "wallet-tool";
          };

          # This package is an example of an escape hatch
          wallettemplate = stdenv.mkDerivation {
            pname = "wallettemplate";
            inherit version src;

            # Disable the Nix build sandbox for this specific build.
            # This means the build can freely talk to the Internet.
            __noChroot = true;

            nativeBuildInputs = [gradle pkgs.makeWrapper];

            buildPhase = ''
              export GRADLE_USER_HOME=$(mktemp -d)
              gradle --no-daemon bitcoinj-wallettemplate:installDist
            '';

            installPhase = ''
              mkdir -p $out/share/vanilla
              cp -r wallettemplate/build/install/bitcoinj-wallettemplate/* $out/share/vanilla
              makeWrapper $out/share/vanilla/bin/bitcoinj-wallettemplate $out/bin/bitcoinj-wallettemplate \
                    --set JAVA_HOME ${jdk}
            '';

            meta.mainProgram = "bitcoinj-wallettemplate";
          };
        };
      };
    };
}
