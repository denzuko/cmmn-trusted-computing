# CLAUDE.md — cmmn-trusted-computing

| Field | Value |
|---|---|
| Application | cmmn-trusted-computing |
| Description | BMAC lab: CMMN-modelled ELF binary trusted computing from Lisp codebases |
| Type | lisp-actor |
| Version | 0.1.0 |
| Branch | develop |
| Licence | BSD 3-Clause |
| Organisation | denzuko |

---

## Standards Stack

- **BDD:** sunny-side (Gherkin), FiveAM
- **Documentation:** 40ants-doc (Ultralisp)
- **CI:** 40ants-ci (defworkflow)
- **Governance:** dps-meta@v1
- **Identity:** org.cispec.* labels on all ELF outputs
- **Signing:** elfsign (ELF section), cosign (keyless Sigstore), step-ca (PKI)
- **Dependency management:** qlot
- **Branching:** git-flow, default branch `develop`

---

## BDD Workflow

```
.feature → sunny-side scenario → FiveAM spec → implementation → gate → merge
```

The `.feature` file is the specification. No code is written before the feature file exists. No feature file is written before the BDD scenario is reviewed.

---

## Semver Rules

- MAJOR: public API or ELF ABI break
- MINOR: new non-breaking capability
- PATCH: everything else (freely exceeds 100)

---

## Subcommands

```
./cmmn-trusted-computing.ros build      ; compile binary
./cmmn-trusted-computing.ros sign       ; elfsign + cosign attest
./cmmn-trusted-computing.ros verify     ; libcimatrix gate check
./cmmn-trusted-computing.ros status     ; show case state
./cmmn-trusted-computing.ros decommission
```

---

## Do Not

- Write `if` where `when`/`unless`/`cond` is correct
- Write comments — the feature file and docstrings carry the spec
- Write docstrings as narrative or debug history
- Coin hyphenated words for concepts that do not yet have names
- Use MIT or GNU-family licences
- Run `sudo` — use `doas`
- Write source form tracking — `sb-c:*source-location-store-source-form-p*` must remain `nil`
- Commit without running the gate script
