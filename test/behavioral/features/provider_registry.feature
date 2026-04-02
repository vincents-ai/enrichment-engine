Feature: Provider Registry
  As a GRC compliance engineer
  I want to register and run GRC providers
  So that I can populate the control database

  Scenario: List all registered providers
    When I list all registered providers
    Then the registry should contain at least 45 providers

  Scenario: Get a specific provider by name
    When I request the "hipaa" provider
    Then the provider should be available
    And the provider name should be "hipaa"

  Scenario: Get a nonexistent provider
    When I request the "nonexistent" provider
    Then the provider should not be available

  Scenario: Run a single provider
    Given a storage backend is available
    When I run the "gdpr" provider
    Then at least 25 controls should be written

  Scenario: Run all providers
    Given a storage backend is available
    When I run all providers
    Then at least 500 total controls should be written
