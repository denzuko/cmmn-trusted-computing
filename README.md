# BMAC Lab: Obfuscated Trusted Computing via CMMN and ELF Binaries from Lisp Codebases

**Status:** Active Lab  
**Series:** Durable Systems  
**Branch model:** git-flow (`develop` default)  
**License:** BSD 3-Clause  
**Scaffold:** Fork of `denzuko/todo-app-deploy`

---

## Scope

This lab investigates three intersecting concerns:

1. **CMMN (Case Management Model and Notation)** as a workflow substrate for trusted-computing audit trails — modelling the lifecycle of an ELF binary from Lisp source through signing and attestation as a CMMN case.

2. **ELF binary obfuscation from Lisp codebases** — specifically `sb-ext:save-lisp-and-die` compiled outputs hardened via:
   - `(declaim (optimize (debug 0) (speed 3) (safety 1)))` to strip debug metadata
   - `(setf sb-c:*source-location-store-source-form-p* nil)` to clear source form tracking
   - `elfsign` post-compilation signing
   - `cosign` keyless attestation via Sigstore
   - `step-ca` as the internal PKI for short-lived signing certificates

3. **cispec compliance** — every produced ELF carries `org.cispec.*` identity labels, and the build pipeline gates on `libcimatrix` validation before any signing step runs.

---

## Repository Layout (fork of todo-app-deploy)

```
.
├── cmmn-trusted-computing.asd      ; umbrella ASDF namespace (empty root)
├── cmmn-trusted-computing.ros      ; thin CLI wrapper
├── src/
│   ├── cmmn-trusted-computing/
│   │   ├── core.lisp               ; domain model (case, stage, task, artifact)
│   │   ├── pipeline.lisp           ; build → sign → attest pipeline DSL
│   │   ├── signing.lisp            ; elfsign + cosign integration
│   │   ├── pki.lisp                ; step-ca certificate lifecycle
│   │   └── cispec.lisp             ; org.cispec label injection + libcimatrix gate
├── t/
│   ├── features/
│   │   ├── pipeline.feature        ; BDD: build pipeline stages
│   │   ├── signing.feature         ; BDD: elfsign + cosign flows
│   │   ├── pki.feature             ; BDD: step-ca cert lifecycle
│   │   └── cispec.feature          ; BDD: org.cispec label compliance
│   └── spec.lisp                   ; FiveAM suites fulfilling each .feature
├── docs/
│   ├── whitepaper.md               ; primary research output
│   ├── linkedin-article.md         ; LinkedIn long-form
│   ├── bmac-article.md             ; BMAC member post
│   └── dwightaspencer-post.md      ; dwightaspencer.com "Durable Systems" entry
├── Makefile
├── qlfile
├── qlfile.lock
└── CLAUDE.md
```

---

## Engineering Practices (established, not negotiated)

### BDD-first order
```
.feature file → sunny-side scenario → FiveAM spec → implementation
```
Comments are antipattern. The `.feature` file is the spec. The FiveAM suite is the contract. The code fulfils it.

### Declare block (all compiled files)
```lisp
(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)
```
Placed at the top of every `.lisp` source file in `src/`. Not in test files.

### Combinatoric discipline
`unless`/`when`/`cond` are first-class. `if` is explicit branching and flags a gate violation.

### Docstrings
Contract and non-obvious caveats only. No history, no narrative, no first-person.

### Sign / attest chain
```
sbcl --dump → elfsign (ELF section .note.signature) → libcimatrix gate →
cosign sign (keyless, Sigstore OIDC) → step-ca short-lived cert
```

---

## Bootstrap

```bash
# Prerequisites
gh auth login
ros install qlot
gh repo clone denzuko/todo-app-deploy cmmn-trusted-computing
cd cmmn-trusted-computing

# Toolchain
sudo apt-get install -y sbcl step-cli cosign elfsign

# Deps
qlot add ultralisp 40ants-doc
qlot add ql sunny-side
qlot add ql fiveam
qlot add ql bknr-datastore

# Build
make build

# BDD gate
make test

# Sign + attest
make dist
```

---

## Makefile targets

| Target | Action |
|--------|--------|
| `build` | Compile SBCL binary with optimise + strip flags |
| `test` | sunny-side BDD runner → FiveAM suite |
| `dist` | elfsign → libcimatrix gate → cosign attest |
| `install` | Deploy via Consfigurator defhost |
| `doc` | 40ants-doc render → build/docs/ |
| `clean` | Remove build artifacts |
