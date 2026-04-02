Feature: Enrichment Pipeline
  As a security analyst
  I want to map vulnerabilities to compliance controls
  So that I can assess regulatory impact

  Scenario: CWE-based vulnerability mapping
    Given a vulnerability "CVE-2024-TEST" with CWE "CWE-79"
    And a control "TEST_CTRL" with RelatedCWE "CWE-79"
    When I run the CWE mapping phase
    Then a mapping should exist from "CVE-2024-TEST" to "TEST_CTRL"
    And the mapping type should be "cwe"
    And the mapping confidence should be 0.8

  Scenario: SBOM enrichment
    Given an SBOM with component "log4j-core" version "2.14.0"
    And the component has CPE "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
    And at least 1 control exists in storage
    When I enrich the SBOM
    Then the enriched component should have compliance metadata
    And the compliance risk should be "needs-review"

  Scenario: Empty vulnerability database
    Given no vulnerabilities in storage
    And at least 1 control exists in storage
    When I run the full enrichment pipeline
    Then 0 mappings should be created
    And the result should report 0 mappings
