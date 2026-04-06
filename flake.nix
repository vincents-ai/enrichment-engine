{
  description = "enrichment-engine - GRC compliance enrichment and vulnerability-to-control mapping";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    vulnz.url = "path:/home/shift/Documents/d-stack-desktop/vulnz-go";
  };

  outputs = { self, nixpkgs, flake-utils, vulnz }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "enrichment-engine";
          version = "0.1.0";
          src = ./.;
          proxyVendor = true;
          vendorHash = "sha256-hdsOYOrNs2b8mGCSJ0wcYcZazuYLYx0TQHjjjG3aP04=";
          doCheck = false;
          subPackages = [ "cmd/enrich" ];
          ldflags = [
            "-s" "-w"
            "-X main.Version=0.1.0"
          ];
          postPatch = ''
            cp -r ${vulnz} vendor-shift-vulnz
            chmod -R u+w vendor-shift-vulnz
            sed -i 's|replace github.com/shift/vulnz => .*|replace github.com/shift/vulnz => ./vendor-shift-vulnz|' go.mod
          '';
          meta = with pkgs.lib; {
            description = "GRC compliance enrichment engine - maps vulnerabilities to control frameworks";
            homepage = "https://github.com/shift/enrichment-engine";
            license = licenses.agpl3Only;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        packages.enrich = self.packages.${system}.default;

        checks = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          full-workflow = pkgs.testers.nixosTest (import ./nix/tests/full-workflow.nix { inherit self pkgs; });
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            golangci-lint
            sqlite
            jq
            syft
            grype
            cyclonedx-cli
          ];

          shellHook = ''
            export ENRICH_WORKSPACE="''${ENRICH_WORKSPACE:-./data}"
            export ENRICH_LOG_LEVEL="''${ENRICH_LOG_LEVEL:-info}"
            echo "enrichment-engine development environment loaded."
            echo "Workspace: $ENRICH_WORKSPACE"
          '';
        };
      }
    );
}
