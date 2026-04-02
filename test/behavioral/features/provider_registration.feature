Feature: Provider Registration
  As a GRC compliance engineer
  I want all providers to be properly registered
  So that the enrichment engine can use them

  Scenario: All 45 providers are registered
    When I list all registered providers
    Then the registry should contain at least 45 providers

  Scenario: Provider names are unique
    When I list all registered providers
    Then the provider names should be unique

  Scenario: Each provider has a valid name format
    When I list all registered providers
    Then each provider name should match the valid name format
