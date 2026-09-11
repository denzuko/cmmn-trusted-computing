Feature: ELF binary signing and keyless attestation

  As a security engineer
  I need every compiled ELF binary to carry a cryptographic signature and a Sigstore attestation
  So that downstream consumers can verify provenance without trusting the build host

  Background:
    Given the build pipeline has produced a valid ELF binary
    And the CMMN case is in "LabelInjection Completed" state

  Scenario: elfsign embeds signature in ELF note section
    Given a compiled ELF binary
    When elfsign runs with the current signing key
    Then the binary has a .note.signature ELF section
    And the section contains a valid RSA-PSS signature over the binary content
    And the CMMN signing stage transitions to "Completed"

  Scenario: cosign attests via Sigstore OIDC keyless flow
    Given a signed ELF binary
    And a valid OIDC token from step-ca
    When cosign attest runs
    Then a Rekor log entry exists for the binary digest
    And the attestation payload includes the org.cispec labels
    And the CMMN attestation stage transitions to "Completed"

  Scenario: Signing is blocked when libcimatrix gate fails
    Given a compiled ELF binary with missing org.cispec labels
    When the libcimatrix gate runs
    Then the gate exits non-zero
    And elfsign does not run
    And the CMMN signing stage transitions to "Blocked"

  Scenario: Signature verification passes on untampered binary
    Given a signed and attested ELF binary
    When cosign verify runs against the Rekor log
    Then verification succeeds
    And the CMMN verification stage transitions to "Completed"

  Scenario: Signature verification fails on tampered binary
    Given a signed ELF binary with one byte modified after signing
    When cosign verify runs against the Rekor log
    Then verification fails with a digest mismatch
    And the CMMN case opens an exception task "TamperDetected"
