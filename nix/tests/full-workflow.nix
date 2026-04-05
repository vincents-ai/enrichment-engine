{ self, pkgs }:

let
  enrich = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
in
{
  name = "enrich-full-workflow";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [ enrich pkgs.jq ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # 1. Version check
    out = machine.succeed("enrich version")
    assert "enrichment-engine" in out, f"version output: {out}"

    # 2. Providers list
    out = machine.succeed("enrich providers")
    assert "hipaa" in out.lower(), f"providers: {out}"
    assert "pci_dss" in out.lower(), f"providers: {out}"

    # 3. Create workspace and sample NVD JSON
    machine.succeed("mkdir -p /tmp/e2e-workspace")

    machine.succeed("""
      cat > /tmp/e2e-workspace/log4shell.json << 'CVEEOF'
    {"id":"CVE-2021-44228","cve":{"id":"CVE-2021-44228","published":"2021-12-10T18:15:00.000Z","descriptions":[{"lang":"en","value":"Apache Log4j2..."}],"weaknesses":[{"description":[{"lang":"en","value":"CWE-502"}]}],"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}]}]}]}}
    CVEEOF
    """)

    # 4. Ingest
    out = machine.succeed("enrich -w /tmp/e2e-workspace -l error ingest -f /tmp/e2e-workspace/log4shell.json")
    assert "1 vulnerabilities" in out, f"ingest: {out}"

    # 5. Status (pre-enrichment)
    out = machine.succeed("enrich -w /tmp/e2e-workspace status")
    assert "Vulnerabilities: 1" in out, f"status pre: {out}"

    # 6. Run enrichment pipeline
    machine.succeed("enrich -w /tmp/e2e-workspace -l error run --all --max-parallel 1")

    # 7. Status (post-enrichment) — should have controls and mappings
    out = machine.succeed("enrich -w /tmp/e2e-workspace status")
    assert "Controls:" in out, f"status post: {out}"
    assert "Mappings:" in out, f"status post: {out}"

    # 8. Export to file
    machine.succeed("enrich -w /tmp/e2e-workspace -l error export -o /tmp/e2e-workspace/bom.json")
    out = machine.succeed("cat /tmp/e2e-workspace/bom.json")
    parsed = machine.succeed("jq .bomFormat /tmp/e2e-workspace/bom.json")
    assert "CycloneDX" in parsed, f"export: {parsed}"

    # 9. Export to stdout
    out = machine.succeed("enrich -w /tmp/e2e-workspace -l error export")
    assert "CycloneDX" in out, f"stdout export: {out[:100]}"

    # 10. Verify BOM has vulnerabilities with mappings
    vuln_count = machine.succeed("jq '.vulnerabilities | length' /tmp/e2e-workspace/bom.json")
    assert int(vuln_count.strip()) > 0, f"no vulnerabilities in BOM: {vuln_count}"
  '';
}
