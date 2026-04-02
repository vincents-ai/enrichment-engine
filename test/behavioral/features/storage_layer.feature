Feature: Storage Layer
  As a system component
  I want a reliable storage layer
  So that GRC data persists correctly

  Scenario: Controls can be written and read back
    Given an empty database
    When I write a control with composite ID "STORE/CTRL-1", framework "NIST_CSF", title "Risk Assessment"
    And I read the control with composite ID "STORE/CTRL-1"
    Then the control data should be valid JSON with framework "NIST_CSF"
    And the control data should have title "Risk Assessment"

  Scenario: Mappings preserve all fields
    Given an empty database
    When I write a mapping from vulnerability "CVE-2024-MAP" to control "FW/CTRL-1" with type "cwe", confidence 0.8, and evidence "CWE-79 shared"
    And I list mappings for vulnerability "CVE-2024-MAP"
    Then the mapping should have control "FW/CTRL-1"
    And the mapping should have type "cwe"
    And the mapping should have confidence 0.8
    And the mapping should have evidence containing "CWE-79"

  Scenario: Framework filtering returns only matching controls
    Given an empty database
    When I write a control with composite ID "FILT/A-1", framework "HIPAA", title "HIPAA Control"
    And I write a control with composite ID "FILT/B-1", framework "PCI_DSS", title "PCI Control"
    And I list controls for framework "HIPAA"
    Then at least 1 control should be returned
    And all returned controls should have framework "HIPAA"
