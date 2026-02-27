{
  description = "bitcoinj";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs = inputs @ { self, nixpkgs, ... }:
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
        graalvm = pkgs.graalvmPackages.graalvm-ce;
        in {
        default = pkgs.mkShell {
          packages = with pkgs ; [
                graalvm                    # This JDK will be in PATH
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = graalvm;        # Run Gradle with this JDK
                })
            ];
          shellHook = ''
            # setup GRAALVM_HOME
            export GRAALVM_HOME=${graalvm}
            echo "Welcome to bitcoinj!"
          '';
        };
      });
      packages = forEachSystem (system: {
        wallet-tool =
          let
            pkgs = import nixpkgs {
              inherit system;
            };
            mainProgram = "wallet-tool";
            mainClass = "org.bitcoinj.wallettool.WalletTool";
            gradle = pkgs.gradle_9.override { java = pkgs.jdk21_headless; };
            jre = pkgs.jdk21_headless;  # JRE to run the example with (jre21_minimal doesn't include java.logging)
            derivation = pkgs.stdenv.mkDerivation (_finalAttrs: {
              pname = mainProgram;
              version = "0.18-SNAPSHOT";
              meta = {
                inherit mainProgram;
              };

              src = self;  # project root is source

              nativeBuildInputs = [gradle pkgs.makeWrapper];

              mitmCache = gradle.fetchDeps {
                pkg = derivation;
                # update or regenerate this by running:
                #  $(nix build .#wallet-tool.mitmCache.updateScript --print-out-paths)
                data = ./nix-deps.json;
              };

              gradleBuildTask = "bitcoinj-wallettool:installDist";

              gradleFlags = [ "--info --stacktrace" ];

              # will run the gradleCheckTask (defaults to "test")
              doCheck = false;

              installPhase = ''
                mkdir -p $out/{bin,share/${mainProgram}/lib}
                cp wallettool/build/install/wallet-tool/lib/*.jar $out/share/${mainProgram}/lib
                # Compute CLASSPATH: all .jar files in $out/share/${mainProgram}/lib
                export MYPATH=$(find $out/share/${mainProgram}/lib -name "*.jar" -printf ':%p' | sed 's|^:||')  # Colon-separated, no leading :

                makeWrapper ${jre}/bin/java $out/bin/${mainProgram} \
                   --add-flags "-cp $MYPATH ${mainClass}" \
              '';
            });
          in
          derivation;
      });
  };
}
