+++
title = "Trusted Computing from a Lisp Codebase"
slug = "trusted-computing-lisp-codebase"
date = 2026-09-11
series = ["durable-systems"]
tags = ["lisp", "security", "sbcl", "elf", "cmmn", "cispec", "signing"]
+++

The standard Lisp deployment story ends at `save-lisp-and-die`. The binary is large, the source metadata is present, and the provenance is a shell script no one reads. This post covers a different path.

---

## What the Binary Contains by Default

SBCL's default optimisation policy is `(debug 2)`. At that level the compiler stores:

- DWARF debug sections (`.debug_info`, `.debug_line`, `.debug_abbrev`)
- Source location records in the image heap
- Interactive debugger restart descriptions

None of these survive a `--strip-debug` pass applied to the ELF binary — except the heap contents, which `strip` does not touch because it does not know they exist. The source location records live in the SBCL heap, not in ELF sections. `strings ./output | grep defun` will find them.

Two settings remove them at compile time:

```lisp
(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)
```

Both go at the top of every source file. The `declaim` form sets the global optimisation policy before any compilation. `*source-location-store-source-form-p* nil` prevents the compiler from storing the original source form for each expression. These settings propagate to everything loaded after them; anything loaded before them can still produce debug metadata. File order matters.

What remains after both settings: the SBCL runtime identity, exported symbol names, package names as strings. A complete forensic analyst will identify this as an SBCL binary. A casual `strings` pass will not recover the source structure.

---

## The Signing Chain

A binary with no source metadata is harder to reverse. It is still trivially substitutable. Cryptographic provenance addresses that separately.

Three tools compose well for ELF outputs from Lisp builds:

**elfsign** signs the binary by embedding an RSA-PSS signature in a `.note.signature` ELF section. The signature covers all other sections, so any post-signing modification — including writing to the ELF notes section — invalidates it. The constraint this creates: everything that needs to be in the binary must be written before elfsign runs.

**cosign** provides keyless attestation via Sigstore. The build host exchanges an OIDC token for an ephemeral certificate from Fulcio, signs a predicate document (binary SHA-256 digest plus identity labels), and publishes the result to the Rekor transparency log. Verification needs only the Rekor endpoint; no private key lives on the deployment host.

**step-ca** is the internal PKI. It issues both the OIDC tokens cosign needs and the short-lived signing certificates (15-minute TTL) that elfsign uses. The CA root fingerprint is embedded in the binary before elfsign runs. A binary signed by a different PKI instance carries a different fingerprint; the mismatch is detectable at verification time without trusting any metadata the binary asserts about itself.

The ordering constraint is not optional: `org.cispec` label injection → elfsign → cosign. Labels before signing because elfsign covers the notes section. cosign after elfsign because the predicate document attests the post-signing digest.

---

## CMMN as the Pipeline Model

The signing chain without a structured pipeline model is a shell script with four failure modes and no exception handling. CMMN — Case Management Model and Notation, the OMG standard — is the correct model for this shape of work.

The OMG designed CMMN for case work: structured stages, discretionary tasks, exception paths, milestone markers. A build-sign-attest pipeline fits the model naturally. Each run is a case. Each step is a stage. Failures open exception tasks. The case record is queryable long after the pipeline run completes.

The operational argument for CMMN over a plain state machine is the exception task design. A `BuildFailure` exception task carries the compiler output and the source commit. A `TamperDetected` exception task carries the pre- and post-tamper digests and the Rekor result. A `CertExpired` exception task carries the certificate serial and the expiry timestamp. A state machine models the happy path; CMMN models the full case including the paths that matter most operationally.

The case store is backed by `bknr.datastore`. Case objects are persistent CLOS instances. The audit log is a list slot on the case object, appended at each stage transition. The case record is not a log file; it is a queryable object in the same store as the application's other persistent data.

---

## org.cispec Labels

Every binary this pipeline produces carries six identity labels in its ELF notes section:

- `org.cispec.application` — application name
- `org.cispec.managed-by` — governance tool
- `org.cispec.fqdn` — deployment target
- `org.cispec.service-account` — OS account
- `org.cispec.version` — semver string
- `org.cispec.pki-root` — CA root fingerprint

These labels come from the `org.cispec.*` namespace defined by `cispec.org`. The `libcimatrix` C99 library validates all six before any signing step runs. A binary missing any label cannot reach the signing step. The gate exits non-zero and names the missing field.

This is the mechanism that makes the provenance chain coherent. The cosign attestation includes the `org.cispec` labels in the predicate document. The Rekor entry therefore contains both the binary digest and the identity claim. A deployment host that receives the binary can verify both the digest (via cosign) and the label values (via libcimatrix) in a single verification pass.

---

## The Development Discipline

The implementation follows the denzuko org's established BDD-first workflow:

```
.feature file → sunny-side scenario → FiveAM spec → implementation
```

Four `.feature` files describe the complete behaviour of the pipeline before any Lisp source was written. The FiveAM suite fulfils each Gherkin scenario. Comments do not appear in the source — the `.feature` files carry the specification, the docstrings carry the contract. The gate script scans for bare `(if ...)` forms and rejects them in favour of `when`/`unless`/`cond`.

This is not a workflow preference. It is the standard that the denzuko org's gate enforces on every commit. The gate runs before every push. The commit does not land without a passing gate.

---

## The Durable Systems Argument

The "Durable Systems" thesis — that systems built on standards and ownership outlast systems built on connectors and subscriptions — applies directly here.

A Lisp binary produced by this pipeline can be verified in 2036 using the same three tools (`elfsign`, `cosign verify`, `readelf`) without any dependency on the build system that produced it. The Rekor entry is permanent. The `org.cispec` labels are in the binary. The signing certificate is revoked and irrelevant to verification.

Compare that to a CI-platform-native signing workflow: the provenance record lives in the CI platform's database. When the platform changes its API, the verification steps change. When the platform is discontinued, the provenance record is gone. The binary survives; the provenance does not.

Standards and ownership. The binary owns its own provenance. That is the durable outcome.

---

Code and whitepaper: `denzuko/cmmn-trusted-computing`  
Full series index: dwightaspencer.com/series/durable-systems
