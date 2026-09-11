# Lab Findings: Obfuscated Trusted Computing from Common Lisp Codebases

## Hypothesis

A single step-ca intermediate could serve as the chain of trust for elfsign,
IMA/EVM, SELinux/AppArmor policy validation, cosign attestation, SBOM, and
CMMN case registration in Zot simultaneously.

## What Was Tested

Environment: Ubuntu 24.04, SBCL 2.6.8, kernel $(uname -r)
Tools: evmctl 1.4, step 0.30.6, cosign 2.x, openssl 3.0.13

---

## Finding 1: evmctl + step-ca works at the signing layer

evmctl ima_sign accepts a step-ca leaf key directly:

```
evmctl ima_sign \
  --key /tmp/pki/signing.key \
  --keyid-from-cert /tmp/pki/signing.crt \
  --hash sha256 \
  <binary>
```

Result: security.ima xattr written, keyid derived from cert SKID.
The signing key and cert chain are the same step-ca leaf issued from
the intermediate. This part of the hypothesis holds.

---

## Finding 2: IMA kernel enforcement requires CONFIG_INTEGRITY

The .ima keyring does not exist on this host:

```
keyctl show %:.ima  →  Can't find 'keyring:.ima'
grep CONFIG_INTEGRITY /boot/config-*  →  # CONFIG_INTEGRITY is not set
```

The xattr is written but nothing enforces it at exec time. IMA appraisal
is a kernel compile-time feature, not a runtime configuration. On hosts
without CONFIG_INTEGRITY=y + CONFIG_IMA_APPRAISE=y, the entire IMA layer
is absent regardless of xattr state.

Consequence: the architecture splits at this point.

  IMA hosts:   xattr is enforced at execve() by the kernel
  Non-IMA hosts: xattr is ignored, elfsign is the only integrity gate

The step-ca intermediate cannot bridge this gap — it is a PKI question,
not a key format question.

---

## Finding 3: Loading step-ca into the IMA keyring requires kernel trust

Even on IMA-enabled hosts, loading the step-ca intermediate into .ima
requires it to be signed by a key already in .builtin_trusted_keys or
.machine (MOK). On stock kernels, .builtin_trusted_keys contains only
the distro's signing key.

Options:
  a) Enroll step-ca root into MOK at image build time (mokutil --import)
  b) Build a custom kernel with step-ca root as a builtin trusted key
  c) Use a CA that is already trusted by the kernel (distro CA, not step-ca)

Option (a) is the practical path for trusted VM hosts — enroll at image
provisioning time via Consfigurator defhost.

---

## Finding 4: cosign with step-ca key works but requires Rekor or local config

cosign sign-blob with --key accepts the step-ca leaf key directly.
Without Rekor, cosign attempts Fulcio (keyless OIDC flow) by default
and times out.

With --signing-config pointing to a config with rekorTlogUrls removed,
cosign still attempts Fulcio for the certificate. Pure key-based signing
without any Sigstore infrastructure requires:

  cosign sign-blob --key <key> --bundle <out> --insecure-skip-verify

Or running a self-hosted Rekor instance and pointing cosign at it.
The public Sigstore infrastructure assumes keyless OIDC; key-based
signing is supported but the CLI defaults push toward keyless.

---

## Finding 5: The single-chain-of-trust model partially holds

| Layer         | step-ca chain | Works without IMA kernel |
|---------------|---------------|--------------------------|
| elfsign       | signing.key   | yes (userspace only)     |
| evmctl/IMA    | signing.key   | signs yes, enforces no   |
| cosign        | signing.key   | yes (with local Rekor)   |
| SELinux label | n/a           | separate mechanism       |
| AppArmor      | n/a           | separate mechanism       |

SELinux and AppArmor do not consume the step-ca chain at all. They operate
on file labels and path/capability policy. The connection to the signing
chain is indirect: AppArmor can gate on file hash (aa-logprof + hash rules),
SELinux can gate on file context set at deploy time. Neither reads the
elfsign note section or the IMA xattr cert chain.

The chain of trust is not single — it is parallel:

  step-ca → elfsign + IMA (integrity)
  distro CA / MOK → IMA kernel keyring (enforcement)
  SELinux/AppArmor policy → separate trust domain entirely

---

## What the Architecture Actually Looks Like

```
compile (debug 0)
  │
  ▼
step-ca issue leaf cert (24h TTL)
  │
  ├─→ evmctl ima_sign (security.ima xattr, keyid from SKID)
  │     enforced only on CONFIG_IMA_APPRAISE kernels
  │     requires step-ca root in MOK on those hosts
  │
  ├─→ openssl/cosign sign (detached sig or bundle)
  │     attests binary + cert chain
  │     self-hosted Rekor or public Sigstore
  │
  └─→ step-ca cert revoked after signing (15m TTL)

deploy
  │
  ├─→ IMA hosts: kernel checks security.ima at execve()
  ├─→ all hosts: elfsign/openssl sig checked by deploy tooling
  ├─→ SELinux: restorecon sets file context (separate from sig chain)
  └─→ AppArmor: hash rule optionally gates on file content hash

attest
  │
  └─→ cosign bundle → Rekor entry → SBOM external reference → CMMN case → Zot OCI artifact
```

---

## Confirmed Falsehood in Original Hypothesis

The step-ca intermediate cannot be "loaded into IMA" in the sense of
being universally enforced. IMA enforcement is kernel-compiled and
requires MOK enrollment at image build time. On non-IMA hosts, the
security.ima xattr is decorative.

SELinux and AppArmor do not validate the signing key or cert chain.
They validate labels and hashes independently.

The architecture works but the trust chain is not single — it is
three parallel chains that share a PKI root but enforce at different
layers via different mechanisms.

---

## Next Steps for the Lab

1. Provision a VM with CONFIG_IMA_APPRAISE=y and test full enforcement
2. Implement mokutil --import of step-ca root in Consfigurator defhost
3. Self-hosted Rekor via Zot or rekor-server for air-gapped attestation
4. AppArmor profile generation from the signed binary hash
5. CMMN case as OCI artifact in Zot — test media type and queryability
