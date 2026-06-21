{
  description = "A Nix-flake-based Rust development environment";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # unstable Nixpkgs
    fenix = {
      url = "https://flakehub.com/f/nix-community/fenix/0.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.self.overlays.default
              ];
            };
          }
        );
    in
    {
      overlays.default = final: prev: {
        rustToolchain =
          with inputs.fenix.packages.${prev.stdenv.hostPlatform.system};
          combine (
            with stable;
            [
              clippy
              rustc
              cargo
              rustfmt
              rust-src
            ]
          );

        sniproxy-ng = final.callPackage ./nix/package.nix {
          rustPlatform = final.makeRustPlatform {
            rustc = inputs.fenix.packages.${final.stdenv.hostPlatform.system}.stable.rustc;
            cargo = inputs.fenix.packages.${final.stdenv.hostPlatform.system}.stable.cargo;
          };
        };
      };

      packages = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.sniproxy-ng;
        sniproxy-ng = pkgs.sniproxy-ng;
      });

      apps = forEachSupportedSystem ({ pkgs }: {
        default = {
          type = "app";
          program = "${pkgs.sniproxy-ng}/bin/sniproxy-ng";
          meta = {
            description = "Run the sniproxy-ng binary";
          };
        };
        sniproxy-ng = inputs.self.apps.${pkgs.stdenv.hostPlatform.system}.default;
      });

      checks = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.sniproxy-ng;
      });

      nixosModules = rec {
        default = import ./nix/module.nix;
        sniproxy-ng = default;
      };

      devShells = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              openssl
              pkg-config
              cargo-deny
              cargo-edit
              cargo-watch
              rust-analyzer
            ];

            env = {
              # Required by rust-analyzer
              RUST_SRC_PATH = "${pkgs.rustToolchain}/lib/rustlib/src/rust/library";
            };
          };
        }
      );
    };
  }
