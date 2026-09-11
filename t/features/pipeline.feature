Feature: SBCL ELF build pipeline with CMMN case tracking

  As a security engineer
  I need to compile a Lisp codebase into a hardened ELF binary
  So that the resulting binary carries no source metadata and is traceable via a CMMN case

  Background:
    Given the CMMN case registry is initialised
    And the cispec identity labels are configured

  Scenario: Compile with debug stripped and speed maximised
    Given a Common Lisp source file with a top-level declaim form
    When the build pipeline runs
    Then the compiled binary has no DWARF debug sections
    And the binary has no source location records
    And the CMMN build stage transitions to "Completed"

  Scenario: Source form tracking is disabled at build time
    Given sb-c:*source-location-store-source-form-p* is nil
    When the compiler processes any form
    Then no source location is stored in the image
    And the CMMN audit log records the setting at build time

  Scenario: Build failure creates a CMMN exception task
    Given a source file with a type error
    When the build pipeline runs
    And compilation fails
    Then the CMMN case opens an exception task "BuildFailure"
    And the pipeline does not proceed to signing

  Scenario: org.cispec labels are injected before signing
    Given a successfully compiled ELF binary
    When the label injection step runs
    Then the binary ELF notes section contains org.cispec.application
    And the binary ELF notes section contains org.cispec.managed-by
    And the binary ELF notes section contains org.cispec.version
    And the CMMN label-injection stage transitions to "Completed"
