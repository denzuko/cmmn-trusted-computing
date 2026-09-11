Feature: org.cispec label compliance via libcimatrix

  As a security engineer
  I need every ELF output to carry a validated set of org.cispec identity labels
  So that the binary is traceable in a CMDB without requiring runtime introspection

  Background:
    Given libcimatrix is installed and the gate script is on PATH

  Scenario: All six required labels are present and non-empty
    Given a compiled ELF binary
    When libcimatrix runs the identity gate
    Then org.cispec.application is present and non-empty
    And org.cispec.managed-by is present and non-empty
    And org.cispec.fqdn is present and non-empty
    And org.cispec.service-account is present and non-empty
    And org.cispec.version is present and non-empty
    And org.cispec.pki-root is present and non-empty
    And the gate exits zero

  Scenario: Missing label causes gate failure
    Given a compiled ELF binary with org.cispec.fqdn absent
    When libcimatrix runs the identity gate
    Then the gate exits non-zero
    And the error output names org.cispec.fqdn as the missing field

  Scenario: Label injection is idempotent
    Given a binary that already carries org.cispec labels
    When the label injection step runs again with identical values
    Then the binary is unchanged
    And the gate exits zero

  Scenario: Version label follows semver
    Given a compiled ELF binary
    When the org.cispec.version label is inspected
    Then it matches the pattern MAJOR.MINOR.PATCH with no pre-release suffix
