# Obfuscated Trusted Computing from Common Lisp Codebases

**Da Planet Security — BMAC Lab Research**  
**Author:** Tony Spencer  
**Series:** Durable Systems  
**Version:** 0.1.0-draft  
**Licence:** BSD 3-Clause

---

## Abstract

This paper presents a model for producing hardened, cryptographically attested ELF binaries from Common Lisp source code, integrating CMMN as a case-management substrate for the build and attestation pipeline. The approach strips SBCL's default debug metadata at compile time, injects `org.cispec` identity labels into the ELF notes section, and chains three independent signing mechanisms — `elfsign`, `cosign` keyless attestation via Sigstore, and short-lived certificates from `step-ca` — before any binary reaches a deployment target. Every transition in that chain is recorded as a CMMN stage, creating a durable, queryable audit trail without coupling the signing toolchain to any specific CI platform. The result is a Common Lisp deployment practice that satisfies SLSA Level 3 provenance requirements, produces binaries with no recoverable source metadata, and stores the provenance record in a structure any case management tool can consume.

---

## 1. Problem Statement

Common Lisp practitioners deploying via `sb-ext:save-lisp-and-die` inherit a default SBCL image that contains source location data, debug information, and internal symbol tables sufficient to partially reconstruct the original source structure. This is not a theoretical concern: the SBCL image format stores source forms for the interactive debugger, and `readelf` will reveal them in any image produced without explicit countermeasures.

Separately, Lisp deployments rarely carry cryptographic provenance. An ELF binary produced by a Lisp build system is typically indistinguishable, from a provenance standpoint, from any other unsigned native binary. There is no standard mechanism to attach a Sigstore attestation, no integration with internal PKI, and no structured record of which source commit produced which binary.

The third gap is workflow. Even where signing tooling exists, the sequence — compile, strip, label, sign, attest — is typically a shell script with no error-state model. A compilation failure does not produce a structured artefact; a signing failure does not open a tracked remediation task; a tamper event on the output is not modelled as a case exception.

This paper addresses all three gaps.

---

## 2. Background

### 2.1 SBCL Image Hardening

SBCL's compiler exposes two knobs relevant to debug metadata:

```lisp
(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)
```

The `declaim` form sets the global optimisation policy. `debug 0` suppresses the generation of DWARF sections and the storage of local-variable metadata. `speed 3` enables all compiler transformations. `safety 1` retains type checks sufficient for correct operation without the full overhead of `safety 3`.

`sb-c:*source-location-store-source-form-p*` controls whether SBCL records the original source form for each compiled expression. Setting it to `nil` before any compilation occurs prevents source forms from entering the image. The setting must be applied before any `load` or `compile-file` call to be effective; placing it at the top of every source file in the codebase is the safe pattern.

Neither setting is sufficient alone. The `debug 0` declaration removes most DWARF data, but some symbol table entries survive. The `*source-location-store-source-form-p*` setting removes the forms, but does not affect the DWARF sections that `debug 1` or higher would generate. Both must be combined.

### 2.2 ELF Binary Signing with elfsign

`elfsign` embeds a cryptographic signature in an ELF note section (`.note.signature`) without modifying the `.text` or `.data` segments. The signature covers the content of all other sections, so any post-signing modification of the binary — including injection of additional ELF sections — invalidates it. This ordering constraint matters: `org.cispec` label injection must precede `elfsign` invocation.

### 2.3 Keyless Attestation via Sigstore

`cosign` implements keyless signing by exchanging an OIDC token (from any conforming provider, including `step-ca`) for a short-lived signing certificate issued by Sigstore's Fulcio CA. The certificate is used to sign a predicate document — in this pipeline, a JSON document containing the binary's SHA-256 digest and its `org.cispec` labels — and the resulting attestation is published to the Rekor transparency log. Subsequent verification requires only the Rekor endpoint; no private key material is retained by the build host.

### 2.4 step-ca as Internal PKI

`step-ca` provides a self-hosted ACME and JWK provisioner CA. In this pipeline it serves two functions: issuing short-lived signing certificates (15-minute TTL) for `elfsign`, and issuing OIDC tokens used by `cosign` for the keyless attestation flow. The CA root fingerprint is embedded in the binary as `org.cispec.pki-root`, creating a binding between the binary and the PKI instance that signed it.

### 2.5 CMMN as Pipeline Substrate

Case Management Model and Notation (CMMN) 1.1 is an OMG standard for modelling work that involves structured stages, discretionary tasks, and exception paths — precisely the shape of a build-sign-attest pipeline. Each run of the pipeline is a CMMN case. Each stage (build, label injection, PKI, sign, attest, verify) is a CMMN stage. Failures open exception tasks. The case record is queryable long after the pipeline run completes.

The choice of CMMN over a plain state machine is deliberate. CMMN supports discretionary tasks (stages that may or may not be triggered depending on case data), milestone markers, and a separation between the case model (the definition) and the case instance (the run). A build pipeline that supports optional re-signing without full rebuild maps naturally to a CMMN case with a discretionary sign stage; a plain state machine requires a new state for every variant.

### 2.6 org.cispec Labels

The `org.cispec.*` namespace is defined by `cispec.org` (denzuko/cispec.org), which specifies 51 terms across identity, registry, financial, lifecycle, custody, and CI-type categories. For ELF binary identity the six required labels are:

| Label | Content |
|---|---|
| `org.cispec.application` | Application name |
| `org.cispec.managed-by` | Governance tool (e.g. `consfigurator`) |
| `org.cispec.fqdn` | Fully qualified domain name of the deployment target |
| `org.cispec.service-account` | Operating system account name |
| `org.cispec.version` | Semver string matching the ASDF system version |
| `org.cispec.pki-root` | SHA-256 fingerprint of the step-ca root certificate |

These labels are injected into the ELF notes section via `objcopy --add-section` and validated by `libcimatrix`, a C99 library with CFFI bindings for Common Lisp, before any signing step runs.

---

## 3. Architecture

### 3.1 Pipeline Stages

```
Source (.lisp)
    │
    ▼
[BUILD]
  sbcl --save-lisp-and-die
  declaim: debug 0, speed 3, safety 1
  *source-location-store-source-form-p* = nil
    │
    ▼  CMMN stage: Build → Completed / Exception(BuildFailure)
    │
[LABEL INJECTION]
  objcopy --add-section .note.org.cispec
  inject: application, managed-by, fqdn,
          service-account, version
    │
    ▼  CMMN stage: LabelInjection → Completed
    │
[PKI]
  step-ca: issue 15m certificate
  embed: org.cispec.pki-root fingerprint
    │
    ▼  CMMN stage: PKI → Completed
    │
[CIMATRIX GATE]
  libcimatrix: validate all six labels
    │ FAIL → CMMN stage: Sign → Blocked
    │
    ▼ PASS
[SIGN]
  elfsign --sign (RSA-PSS, .note.signature)
  step-ca: revoke certificate
    │
    ▼  CMMN stage: Sign → Completed
    │
[ATTEST]
  cosign attest --predicate (sha256 + labels)
  Rekor log entry created
    │
    ▼  CMMN stage: Attest → Completed
    │
[VERIFY]
  cosign verify --rekor-url
    │ FAIL → CMMN exception: TamperDetected
    ▼ PASS → CMMN stage: Verify → Completed
```

### 3.2 CMMN Case Model

The case model has one mandatory stage (Build) and five subsequent stages that each depend on the prior stage reaching Completed. Exception tasks are:

- `BuildFailure` — opened when the SBCL compilation exits non-zero
- `CertExpired` — opened when the step-ca certificate TTL has elapsed before signing
- `TamperDetected` — opened when cosign verify detects a digest mismatch

Each exception task has a discretionary remediation path: `BuildFailure` re-enters the Build stage from clean source; `CertExpired` requests a fresh certificate; `TamperDetected` triggers a full pipeline re-run from source and a security notification.

### 3.3 Signing Ordering Constraint

The ordering is not arbitrary. `elfsign` covers all ELF sections at signing time; any post-signing modification invalidates the signature. The `objcopy` label injection therefore runs before `elfsign`. The `cosign` attestation runs after `elfsign`, because the predicate document it signs contains the binary's SHA-256 digest — which must reflect the post-elfsign state of the binary.

The `libcimatrix` gate runs between label injection and `elfsign`, because it validates the labels that `cosign` will later attest. A binary that fails the gate has no provenance record; it cannot reach a signing step.

### 3.4 Obfuscation Scope and Limits

The combination of `debug 0`, `*source-location-store-source-form-p* nil`, and `save-lisp-and-die :compression t` produces a binary with:

- No DWARF `.debug_*` sections
- No SBCL source location records in the image heap
- No interactive debugger restart descriptions
- Zlib-compressed image data (reducing static analysis surface)

What it does not remove:

- The SBCL runtime itself (the binary identifies as an SBCL image)
- All exported symbol names (Common Lisp symbol interning is not obfuscation)
- The package structure (package names appear as strings in the image)

This is targeted obfuscation of source metadata, not full binary obfuscation. The goal is to prevent casual reconstruction of the source structure via debugger introspection or strings analysis, not to defeat a determined reverse engineering effort. The signing and attestation chain addresses the integrity and provenance goals; the obfuscation addresses the source confidentiality goal for internal tooling.

---

## 4. Implementation

### 4.1 Repository Structure

The implementation is a fork of `denzuko/todo-app-deploy`, following the established umbrella ASDF namespace pattern:

- `cmmn-trusted-computing.asd` — umbrella system (empty root)
- `cmmn-trusted-computing/core` — CMMN case domain model
- `cmmn-trusted-computing/cispec` — org.cispec label injection and libcimatrix gate
- `cmmn-trusted-computing/pki` — step-ca certificate lifecycle
- `cmmn-trusted-computing/signing` — elfsign and cosign integration
- `cmmn-trusted-computing/pipeline` — pipeline DSL orchestrating all stages
- `cmmn-trusted-computing/docs` — 40ants-doc renderer

### 4.2 BDD Workflow

Every stage was specified as a `.feature` file before any implementation code was written:

1. `t/features/pipeline.feature` — build stage and label injection
2. `t/features/signing.feature` — elfsign and cosign flows
3. `t/features/pki.feature` — step-ca certificate lifecycle
4. `t/features/cispec.feature` — org.cispec label compliance

The `sunny-side` BDD engine (denzuko/sunny-side) runs the `.feature` files. FiveAM suites in `t/spec.lisp` fulfil each scenario. No FiveAM test was written before its corresponding Gherkin scenario existed.

### 4.3 Gate Integration

The gate script checks three things before any commit:

1. **Paren balance** — SBCL-native reader (not a naive counter)
2. **Voice gate on docstrings** — no narrative, no first-person, no session history
3. **Bare `(if ...)` scan** — `when`/`unless`/`cond` are the correct forms

The gate does not check for commented-out code because there is none. Comments are antipractice in this codebase; the `.feature` files carry the specification, the docstrings carry the contract, and the FiveAM suite carries the verification.

---

## 5. cispec Compliance in Practice

The `libcimatrix` gate is the enforcement point for `org.cispec` label compliance. It is a C99 library with CFFI bindings invoked as a subprocess from the pipeline. The gate checks:

- All six required labels are present in the ELF notes section
- No label is empty or contains only whitespace
- `org.cispec.version` matches the semver pattern `MAJOR.MINOR.PATCH`
- `org.cispec.pki-root` matches the current step-ca root fingerprint

A gate failure opens no exception task in isolation — it transitions the Sign stage to Blocked, and the pipeline halts. The operator must correct the label configuration and re-run from the label injection stage.

The label injection step is idempotent. Running it twice with identical values produces no change to the binary, which the gate verifies by comparing the SHA-256 digest before and after a second injection pass.

---

## 6. Threat Model

This pipeline addresses the following threats:

| Threat | Control |
|---|---|
| Source reconstruction from debug data | `debug 0` + `*source-location-store-source-form-p* nil` |
| Binary substitution in deployment | elfsign signature verification |
| Build host compromise producing unsigned binary | cosign keyless attestation via Rekor; unsigned binary has no Rekor entry |
| Certificate misuse after signing | step-ca 15m TTL + immediate revocation |
| Label tampering after signing | elfsign covers the label section; any modification invalidates the signature |
| Missing provenance for a binary | libcimatrix gate blocks signing without all six labels |
| CMMN audit log tampering | Rekor entry is immutable; case log is derived from Rekor at query time |

The pipeline does not address: supply-chain attacks on the SBCL toolchain, compromise of the step-ca root key, or adversarial modification of the Rekor log (a transparency log where append-only guarantees depend on the log operator's security posture).

---

## 7. Operational Notes

### Bootstrap

```bash
sudo apt-get install -y sbcl step-cli cosign elfsign
ros install qlot
gh repo clone denzuko/cmmn-trusted-computing
cd cmmn-trusted-computing
qlot add ultralisp 40ants-doc
qlot add ql sunny-side fiveam bknr-datastore cl-ppcre
make build
make test
make dist
```

### Verifying a Binary

```bash
# Verify elfsign signature
elfsign --verify ./cmmn-trusted-computing

# Verify cosign attestation against Rekor
cosign verify --rekor-url https://rekor.sigstore.dev ./cmmn-trusted-computing

# Inspect org.cispec labels
readelf -n ./cmmn-trusted-computing | grep org.cispec

# Run libcimatrix gate independently
cimatrix-gate --elf ./cmmn-trusted-computing
```

### step-ca Configuration

The pipeline requires a `step-ca` instance with a JWK provisioner named `pipeline`. The provisioner must be configured to issue certificates with a maximum TTL of 15 minutes. The CA URL is configured via `*step-ca-url*` in `cmmn-trusted-computing/pki`.

---

## 8. Related Work

**SLSA (Supply chain Levels for Software Artefacts)** — The pipeline satisfies SLSA Level 3 requirements: the build runs in an isolated environment, provenance is generated by the build system itself, signing uses a non-extractable key (Sigstore's ephemeral certificate), and the provenance record is stored in an append-only log (Rekor).

**Consfigurator** — The deployment step (not covered in this paper) uses Consfigurator's `defhost` pattern, consistent with the rest of the `denzuko` deployment infrastructure.

**bknr.datastore** — The CMMN case store is backed by `bknr.datastore`, consistent with the `fediserve` substrate. Case objects are persistent classes; the audit log is a list slot on the case object.

**dps-meta** — The governance scaffolding (CLAUDE.md, org.cispec labels, 40ants-ci workflow) is generated by `dps-meta@v1` from `git config meta.*` keys.

---

## 9. Conclusion

The combination of compile-time source stripping, ELF note section label injection, a three-mechanism signing chain, and CMMN case tracking produces a Lisp deployment practice with properties that informal shell pipelines cannot provide: a queryable provenance record, structured exception handling, and a gate that prevents any unsigned or unlabelled binary from reaching the signing step. The implementation is a direct fork of an established deployment pattern in the denzuko infrastructure, which reduces the integration surface to the four new subsystems: core, cispec, pki, and signing.

The CMMN substrate is the differentiating architectural choice. The signing tools (`elfsign`, `cosign`, `step-ca`) are independent prior art. The `org.cispec` label schema is defined by `cispec.org`. The Gherkin-first development workflow is established practice. CMMN ties them into a structured case that survives the pipeline run and is queryable by any case management system that speaks the standard.

---

## Appendix A: Key Files

| File | Purpose |
|---|---|
| `src/cmmn-trusted-computing/core.lisp` | CMMN case domain model |
| `src/cmmn-trusted-computing/cispec.lisp` | Label injection and libcimatrix gate |
| `src/cmmn-trusted-computing/pki.lisp` | step-ca certificate lifecycle |
| `src/cmmn-trusted-computing/signing.lisp` | elfsign and cosign integration |
| `src/cmmn-trusted-computing/pipeline.lisp` | Pipeline DSL |
| `t/features/*.feature` | BDD specifications (authoritative) |
| `t/spec.lisp` | FiveAM suites |

## Appendix B: Semver

MAJOR changes: ELF label schema revision (breaks `libcimatrix` compatibility), CMMN case model structural change (breaks case store serialisation).

MINOR changes: additional signing mechanisms, new exception task types, new `org.cispec` label support.

PATCH changes: everything else.
