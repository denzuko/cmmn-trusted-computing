Feature: step-ca short-lived certificate lifecycle for signing

  As a security engineer
  I need signing certificates to be short-lived and issued by an internal CA
  So that the signing identity is bound to a known provisioner and expires before it can be misused

  Background:
    Given step-ca is running and reachable
    And the JWK provisioner is configured

  Scenario: Certificate is issued for the build pipeline identity
    Given a build pipeline run with a known CI identity
    When the pipeline requests a certificate from step-ca
    Then a certificate is issued with a 15-minute TTL
    And the certificate subject matches the org.cispec.application label
    And the CMMN PKI stage transitions to "Completed"

  Scenario: Certificate is revoked after use
    Given a short-lived certificate was used to sign an ELF binary
    When the signing step completes
    Then step-ca ACME revocation is called for that certificate serial
    And the CMMN PKI stage records the revocation timestamp

  Scenario: Expired certificate blocks signing
    Given a certificate whose TTL has elapsed
    When elfsign attempts to use it
    Then elfsign exits non-zero with a certificate-expired error
    And the CMMN signing stage transitions to "Blocked"
    And the CMMN case opens an exception task "CertExpired"

  Scenario: CA root fingerprint is pinned in the binary metadata
    Given a signed ELF binary
    When the org.cispec.pki-root label is inspected
    Then it matches the SHA-256 fingerprint of the step-ca root certificate
