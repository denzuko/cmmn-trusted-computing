# BMAC Lab Report: Obfuscated Trusted Computing from Common Lisp Codebases

**Series:** Durable Systems  
**Lab:** BMAC Research  
**Status:** Active

---

## What This Lab Produced

A working model for hardened ELF binary production from Common Lisp source, with CMMN as the pipeline audit substrate and three independent signing mechanisms in sequence. The output is a binary that carries no source metadata, six `org.cispec.*` identity labels validated by `libcimatrix`, an elfsign RSA-PSS signature, and a cosign attestation in the Rekor transparency log — all tracked as stages in a CMMN case that survives the pipeline run.

The implementation is a fork of the existing `todo-app-deploy` pattern. The additions are four ASDF subsystems over the established umbrella namespace structure, a Makefile, four `.feature` files, and a FiveAM spec suite. The BDD-first discipline holds: every stage exists as a named Gherkin scenario before any implementation code.

---

## The Two Problems Worth Separating

### Source metadata in the SBCL image

`sb-ext:save-lisp-and-die` produces an ELF binary that is also a complete SBCL image snapshot. At the default optimisation policy (`debug 1`, no form-storage override), the image contains:

- DWARF `.debug_info`, `.debug_line`, and `.debug_abbrev` sections
- Source location records stored in the heap by the SBCL compiler
- Interactive debugger restart descriptions

All three survive `strip --strip-debug` applied post-build, because they are in the image heap, not in ELF debug sections that `strip` knows to remove.

The correct countermeasures are compile-time:

```lisp
(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)
```

`debug 0` suppresses DWARF generation and local variable metadata. `*source-location-store-source-form-p* nil` prevents the compiler from storing the original source form for each expression. The combination produces an image where `readelf -n` returns no debug sections and `strings | grep defun` returns nothing from the source structure.

What survives: SBCL runtime identification, exported symbol names (interning is not obfuscation), package names as strings. This is targeted source metadata removal, not full binary obfuscation. The goal is to remove the low-effort reconstruction path, not to defeat a motivated reverse engineer with a hex editor.

### Provenance and tamper detection

An SBCL binary with stripped source metadata is still trivially substitutable in a naive deployment pipeline. The signing chain addresses this:

**elfsign** — ELF section signing (`.note.signature`). Covers all other sections. Label injection must precede it; any post-signing modification to any section invalidates the signature.

**cosign keyless attestation** — exchanges a step-ca OIDC token for a Fulcio ephemeral certificate, signs a predicate document containing the binary digest and `org.cispec` labels, publishes to Rekor. Verification is stateless from the deployment host's perspective: Rekor is the source of truth.

**step-ca** — internal PKI. Issues the OIDC token for cosign and the short-lived certificate (15m TTL) for elfsign. Certificates are revoked immediately after use. The CA root fingerprint is embedded as `org.cispec.pki-root` before elfsign runs, creating a binding between the signed binary and the PKI instance.

---

## The CMMN Substrate

The signing chain without CMMN is a shell script with four failure modes and no exception model. CMMN gives the pipeline a structured case with queryable stage status, exception tasks that carry diagnostic context, and a case record that persists after the pipeline run completes.

The six stages are: Build, LabelInjection, PKI, Sign, Attest, Verify.

Three exception tasks are defined: `BuildFailure` (Build stage failure), `CertExpired` (PKI stage — TTL elapsed before signing), `TamperDetected` (Verify stage — Rekor digest mismatch).

The `libcimatrix` gate is the boundary between LabelInjection and Sign. A binary that fails the gate transitions Sign to Blocked and halts the pipeline without opening a discretionary exception task — the operator must fix the label configuration and re-run from LabelInjection. This is an intentional design choice: a missing label is a configuration error, not a case exception.

The CMMN case store is backed by `bknr.datastore`, consistent with the fediserve substrate. Case objects are persistent CLOS instances; the audit log is a list slot on the case object, appended at each stage transition.

---

## The org.cispec Labels

Six labels are required in every ELF binary this pipeline produces:

| Label | Value |
|---|---|
| `org.cispec.application` | Application name |
| `org.cispec.managed-by` | `consfigurator` |
| `org.cispec.fqdn` | Deployment target FQDN |
| `org.cispec.service-account` | OS service account name |
| `org.cispec.version` | Semver string |
| `org.cispec.pki-root` | SHA-256 fingerprint of step-ca root |

These go into the ELF notes section via `objcopy --add-section`. The `libcimatrix` gate validates all six before signing. The gate is a C99 library (`libcimatrix.so`) with CFFI bindings, invoked as a subprocess from the pipeline.

Label injection is idempotent. Running it twice with the same values produces no change to the binary. The gate verifies this by comparing the SHA-256 digest before and after a second injection pass — which also means the gate itself is a functional test of injection idempotency.

---

## The BDD Workflow in Practice

Four `.feature` files were written before any implementation:

- `pipeline.feature` — compile with stripped debug data, source form tracking disabled, labels injected, CMMN build stage transitions
- `signing.feature` — elfsign note section, cosign Rekor entry, gate-blocks-signing, tamper detection
- `pki.feature` — short-lived certificate, revocation, expired cert blocks signing, CA fingerprint pinning
- `cispec.feature` — all six labels present, missing label causes gate failure, idempotency, semver validation

The `sunny-side` BDD engine processes these files. The FiveAM suite in `t/spec.lisp` fulfils each scenario. The gate script scans for bare `(if ...)` forms and flags any that should be `when`/`unless`/`cond`. Comments do not appear in the source because the `.feature` files carry the specification.

This ordering — feature first, spec second, code third — is not optional in the denzuko org. It is the gate. No implementation is reviewed without the corresponding `.feature` file.

---

## What the Threat Model Covers

| Threat | Control |
|---|---|
| Source structure reconstruction | `debug 0` + `*source-location-store-source-form-p* nil` |
| Binary substitution | elfsign signature verification |
| Unsigned binary reaching deployment | cosign gate (no Rekor entry = no attestation) |
| Certificate misuse | 15m TTL + immediate revocation |
| Label tampering after signing | elfsign covers the ELF notes section |
| Missing provenance | libcimatrix gate blocks signing |

What it does not cover: SBCL toolchain compromise, step-ca root key compromise, Rekor log operator failure. These are out of scope for a per-binary signing pipeline and belong in the infrastructure threat model.

---

## Where to Get It

Repository: `denzuko/cmmn-trusted-computing`  
Whitepaper: `docs/whitepaper.md` in the repo  
Series: Durable Systems on dwightaspencer.com

The full code — four ASDF subsystems, four `.feature` files, FiveAM spec suite, Makefile, CLAUDE.md — is in the repository. The whitepaper covers the threat model, architecture, and operational notes in full. The dwightaspencer.com post covers the design reasoning for the CMMN choice.
