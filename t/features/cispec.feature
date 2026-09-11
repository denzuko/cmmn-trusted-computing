Feature: Signed binary emits correct org.cispec identity objects at runtime

  As a security engineer
  I need the signed ELF binary to emit its org.cispec identity at runtime
  So that I can verify the obfuscated binary executes correctly and produces
  the expected structured output

  Background:
    Given the compiled signed and attested ELF binary is available

  Scenario: Binary emits hello world output
    When the binary is executed
    Then stdout contains "Hello, World"
    And the exit code is zero

  Scenario: Binary emits org.cispec.application at runtime
    When the binary is executed
    Then stdout contains org.cispec.application with a non-empty value

  Scenario: Binary emits org.cispec.version matching semver
    When the binary is executed
    Then stdout contains org.cispec.version
    And the version value matches MAJOR.MINOR.PATCH

  Scenario: Binary emits all six org.cispec identity objects
    When the binary is executed
    Then stdout contains org.cispec.application
    And stdout contains org.cispec.managed-by
    And stdout contains org.cispec.fqdn
    And stdout contains org.cispec.service-account
    And stdout contains org.cispec.version
    And stdout contains org.cispec.pki-root

  Scenario: Obfuscated binary produces correct output despite stripped debug data
    Given the binary was compiled with debug 0 and source location tracking disabled
    When the binary is executed
    Then stdout contains "Hello, World"
    And stdout contains org.cispec.application
    And the exit code is zero
