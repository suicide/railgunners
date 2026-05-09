{
  description = "A Nix-flake-based Rust development environment";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "https://flakehub.com/f/nix-community/fenix/0.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      fenix,
      crane,
      ...
    }:

    let
      supportedSystems = with flake-utils.lib.system; [
        x86_64-linux
        aarch64-linux
        x86_64-darwin
        aarch64-darwin
      ];
    in
    {
      overlays.default = final: prev: {
        rustToolchain =
          with fenix.packages.${prev.stdenv.hostPlatform.system};
          combine (
            with stable;
            [
              cargo
              clippy
              rust-src
              rustc
              rustfmt
            ]
          );
      };
    }
    // flake-utils.lib.eachSystem supportedSystems (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain pkgs.rustToolchain;
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || (pkgs.lib.hasInfix "/crates/railgun-artifacts/data/" path)
            || (pkgs.lib.hasInfix "/crates/railgun-core/testdata/poseidon/" path)
            || (pkgs.lib.hasInfix "/crates/railgun-core/src/crypto/poseidon/" path);
        };
        commonArgs = {
          pname = "railgun-rs";
          version = "0.1.0";
          inherit src;
          strictDeps = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        workspaceCheckArgs = commonArgs // { inherit cargoArtifacts; };
        cliPackage = craneLib.buildPackage (
          workspaceCheckArgs
          // {
            inherit cargoArtifacts;
            pname = "railgun-cli";
            cargoExtraArgs = "-p railgun-cli";
          }
        );
      in
      {
        packages = {
          cli = cliPackage;
          default = cliPackage;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          cli-container = pkgs.dockerTools.buildLayeredImage {
            name = "suicide/rrscli";
            tag = "latest";
            contents = [
              cliPackage
              pkgs.cacert
              pkgs.curl
            ];
            config = {
              Cmd = [ "${cliPackage}/bin/railguncli" ];
              Env = [
                "PATH=/bin"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
        };

        checks = {
          build = cliPackage;
          clippy = craneLib.cargoClippy (
            workspaceCheckArgs
            // {
              cargoClippyExtraArgs = "--workspace --all-targets --all-features -- -D warnings";
            }
          );
          tests = craneLib.cargoTest (workspaceCheckArgs // { cargoTestExtraArgs = "--workspace"; });
          fmt = craneLib.cargoFmt {
            inherit src;
            pname = "railgun-rs";
            version = "0.1.0";
          };
          deny = craneLib.cargoDeny workspaceCheckArgs;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            openssl
            pkg-config
            cargo-deny
            cargo-edit
            cargo-watch
            rust-analyzer
            nixfmt

            nodejs
          ];

          env = {
            RUST_SRC_PATH = "${pkgs.rustToolchain}/lib/rustlib/src/rust/library";
          };
        };

        formatter = pkgs.nixfmt;
      }
    );
}
