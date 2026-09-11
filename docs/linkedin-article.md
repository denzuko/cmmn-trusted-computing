# Why Your Lisp Binary Is Leaking Source Code — And How to Stop It

Most engineers who deploy native binaries from Common Lisp codebases have not looked at what `readelf -n` returns on the output. They should.

SBCL's default compilation mode stores source location data in the image heap. The interactive debugger needs it. The problem is that `save-lisp-and-die` does not strip it unless you tell it to, explicitly, before any compilation occurs. The result is a production binary that retains enough source structure for a `strings` pass to give an attacker a working map of your package layout.

Two settings fix this:

```lisp
(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)
```

These go at the top of every source file. Not in the build script. In the source. The compiler processes them in file order; anything that loads before they take effect can still produce debug metadata.

That is the obfuscation half. It is necessary but not sufficient.

---

## The Provenance Half

A stripped binary with no debug data is harder to reverse. It is not harder to substitute. If your deployment pipeline accepts any binary with the right filename, stripping debug data is irrelevant: an attacker who can intercept the binary path gets their code deployed regardless.

The answer is cryptographic provenance. Three tools compose cleanly for Lisp ELF outputs:

**elfsign** embeds an RSA-PSS signature in a `.note.signature` ELF section without touching `.text` or `.data`. Any post-signing modification — including label injection, which is why labels go in first — invalidates it.

**cosign** provides keyless attestation via Sigstore. The build host exchanges an OIDC token for an ephemeral certificate from Fulcio, signs a predicate document containing the binary's SHA-256 digest, and publishes the result to the Rekor transparency log. Verification requires no private key on the deployment host; Rekor is the source of truth.

**step-ca** issues the OIDC tokens and the short-lived certificates (15-minute TTL) used by elfsign. The CA root fingerprint gets embedded in the binary as an `org.cispec.pki-root` label. A binary signed by a different PKI instance carries a different fingerprint; the mismatch is detectable at verification time.

---

## The Audit Trail Half

The sequence compile → label → sign → attest is not self-documenting. A shell script that runs all four steps produces no record of which step failed, which certificate was used, or whether tamper detection triggered on the output.

CMMN — Case Management Model and Notation, the OMG standard — models this naturally. Each pipeline run is a case. Each step is a stage. Failures open exception tasks. The case record survives the pipeline run and is queryable by any case management tool that speaks the standard.

The exception task design is where this pays off operationally. A `BuildFailure` exception task carries the compiler output and the source commit hash. A `TamperDetected` exception task carries the pre- and post-tamper digests and the Rekor verification result. A `CertExpired` exception task carries the certificate serial and the timestamp of expiry. None of this lives in a log file that gets rotated.

---

## What This Looks Like in Practice

The implementation at `denzuko/cmmn-trusted-computing` is a fork of an existing Consfigurator-based deployment pattern. The additions are four ASDF subsystems:

- `/core` — CMMN case domain model (case, stage, exception task, audit log)
- `/cispec` — `org.cispec.*` label injection and libcimatrix validation gate
- `/pki` — step-ca certificate lifecycle
- `/signing` — elfsign and cosign integration

Every stage was specified as a `.feature` file (Gherkin) before any implementation code was written. The FiveAM test suite fulfils each scenario. No code exists that is not covered by a named scenario in a `.feature` file.

The `libcimatrix` gate — a C99 library with CFFI bindings — runs between label injection and elfsign. A binary missing any of the six required `org.cispec` labels cannot reach the signing step. The gate exits non-zero and names the missing field. The pipeline halts.

---

## The Result

A Lisp binary that leaves this pipeline has:

- No DWARF debug sections
- No SBCL source location records in the image heap
- Six `org.cispec.*` identity labels in the ELF notes section
- An RSA-PSS signature in `.note.signature`
- A Rekor transparency log entry linking the binary digest to the org.cispec labels and the signing certificate
- A CMMN case record with a full audit trail of every stage transition

That is what trusted computing from a Lisp codebase looks like when the pipeline is structured rather than scripted.

The full whitepaper and supporting code are available at `denzuko/cmmn-trusted-computing`. The research write-up is on my BMAC page.
