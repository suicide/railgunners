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
        src = craneLib.cleanCargoSource ./.;
        commonArgs = {
          pname = "railgun-rs";
          version = "0.1.0";
          inherit src;
          strictDeps = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in
      {
        packages.default = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "railgun-cli";
            cargoExtraArgs = "-p railgun-cli";
          }
        );

        checks = {
          build = self.packages.${system}.default;
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--workspace --all-targets --all-features -- -D warnings";
            }
          );
          fmt = craneLib.cargoFmt {
            inherit src;
            pname = "railgun-rs";
            version = "0.1.0";
          };
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
