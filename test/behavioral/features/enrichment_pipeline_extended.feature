Feature: Enrichment Pipeline Extended
  As a security analyst
  I want the enrichment pipeline to work correctly
  So that vulnerabilities are mapped to compliance controls

  Scenario: Running enrichment with no data produces zero mappings
    Given no vulnerabilities in storage
    And no controls in storage
    When I run the full enrichment pipeline
    Then 0 mappings should be created
    And the result should report 0 mappings

  Scenario: Running enrichment after loading vulnerabilities and controls produces mappings
    Given a vulnerability "CVE-2024-PIPE" with CWE "CWE-79"
    And a control "PIPE-CTRL" with RelatedCWE "CWE-79"
    When I run the full enrichment pipeline
    Then the result should report at least 1 mappings

  Scenario: CWE-direct mappings have confidence 0.8
    Given a vulnerability "CVE-2024-CWE-CONF" with CWE "CWE-89"
    And a control "CWE-CONF-CTRL" with RelatedCWE "CWE-89"
    When I run the CWE mapping phase
    Then a mapping should exist from "CVE-2024-CWE-CONF" to "CWE-CONF-CTRL"
    And the mapping confidence should be 0.8

  Scenario: CPE-indirect mappings have confidence 0.6
    Given a vulnerability "CVE-2024-CPE-CONF" with CWE "CWE-502" and CPE "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    And a control "CPE-CONF-CTRL" with RelatedCWE "CWE-502"
    When I run the full enrichment pipeline
    Then a mapping should exist from "CVE-2024-CPE-CONF" to "CPE-CONF-CTRL"
    And the mapping type should be "cpe"
    And the mapping confidence should be 0.6

  Scenario: Running enrichment twice is idempotent
    Given a vulnerability "CVE-2024-IDEMP" with CWE "CWE-352"
    And a control "IDEMP-CTRL" with RelatedCWE "CWE-352"
    When I run the full enrichment pipeline
    And I record the mapping count
    And I run the full enrichment pipeline again
    Then the mapping count should remain the same
