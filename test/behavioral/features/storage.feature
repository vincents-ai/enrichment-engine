Feature: Storage Backend
  As a system component
  I want a reliable storage backend
  So that GRC data persists correctly

  Scenario: Write and read a control
    Given an empty database
    When I write a control with ID "TEST/CTRL-1"
    Then reading the control should return valid JSON

  Scenario: List controls by framework
    Given controls exist for framework "ISO_27001_2022"
    When I list controls for framework "ISO_27001_2022"
    Then at least 1 control should be returned

  Scenario: Concurrent control writes
    Given an empty database
    When I write 100 controls concurrently
    Then all 100 controls should be persisted

  Scenario: Database survives close and reopen
    Given a control with ID "TEST/PERSIST-1" exists
    When I close and reopen the database
    Then the control "TEST/PERSIST-1" should still exist
