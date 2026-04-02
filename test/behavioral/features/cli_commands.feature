Feature: CLI Commands
  As a CLI user
  I want to use the enrich command-line tool
  So that I can manage the enrichment engine

  Scenario: enrich providers lists all providers
    When I run the CLI command "providers"
    Then the output should contain "Registered providers"
    And the output should contain "hipaa"
    And the output should contain "gdpr"

  Scenario: enrich version returns valid version string
    When I run the CLI command "version"
    Then the output should match "enrichment-engine v\d+\.\d+\.\d+"

  Scenario: enrich run --provider runs a single provider successfully
    Given a storage backend is available
    When I run the CLI command "run --skip-mapping --provider hipaa"
    Then the command should exit without error
    And the output should contain "Providers complete"
