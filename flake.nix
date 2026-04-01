{
  description = "enrichment-engine - GRC compliance enrichment and vulnerability-to-control mapping";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "enrichment-engine";
          version = "0.1.0";
          
          src = ./.;

          # Update this hash via `nix run nixpkgs#nix-prefetch-go` if go.mod changes
          vendorHash = pkgs.lib.fakeHash;

          subPackages = [ "cmd/enrich" ];

          # CGO required for go-sqlite3
          CGO_ENABLED = "1";

          ldflags = [
            "-s" "-w"
            "-X main.Version=0.1.0"
          ];

          meta = with pkgs.lib; {
            description = "GRC compliance enrichment engine - maps vulnerabilities to control frameworks";
            homepage = "https://github.com/shift/enrichment-engine";
            license = licenses.agpl3Only;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            golangci-lint
            sqlite
            jq
            # OSCAL tooling
            oscal-cli
            # SBOM tools
            syft
            grype
            # Compliance frameworks
            cyclonedx-cli
          ];

          shellHook = ''
            export CGO_ENABLED=1
            export ENRICH_WORKSPACE="''${ENRICH_WORKSPACE:-./data}"
            export ENRICH_LOG_LEVEL="''${ENRICH_LOG_LEVEL:-info}"
            echo "enrichment-engine development environment loaded."
            echo "Workspace: $ENRICH_WORKSPACE"
          '';
        };
      }
    );
}
