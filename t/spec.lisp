(declaim (optimize (debug 3) (speed 1) (safety 3))) ; test files use debug 3

(defpackage #:cmmn-trusted-computing/tests
  (:use #:cl #:fiveam #:cmmn-trusted-computing/core)
  (:import-from #:cmmn-trusted-computing/pipeline
                #:run-pipeline
                #:pipeline-stage-status
                #:pipeline-case-open-p)
  (:import-from #:cmmn-trusted-computing/signing
                #:elfsign-binary
                #:cosign-attest
                #:cosign-verify
                #:elf-has-note-section-p
                #:rekor-entry-exists-p)
  (:import-from #:cmmn-trusted-computing/pki
                #:request-certificate
                #:revoke-certificate
                #:certificate-ttl
                #:certificate-expired-p)
  (:import-from #:cmmn-trusted-computing/cispec
                #:run-cimatrix-gate
                #:inject-labels
                #:read-elf-label
                #:labels-idempotent-p))

(in-package #:cmmn-trusted-computing/tests)

;;; ──────────────────────────────────────────────────────────────────
;;; Top-level suite
;;; ──────────────────────────────────────────────────────────────────

(def-suite cmmn-trusted-computing-suite
  :description "Full BDD-to-spec coverage for CMMN trusted-computing pipeline")

;;; ──────────────────────────────────────────────────────────────────
;;; pipeline.feature
;;; ──────────────────────────────────────────────────────────────────

(def-suite pipeline-suite
  :in cmmn-trusted-computing-suite
  :description "Build pipeline CMMN stage transitions")

(in-suite pipeline-suite)

(test compile-strips-debug-metadata
  "Compiled binary carries no DWARF sections and no source location records."
  (let ((binary (run-pipeline :source "fixtures/hello.lisp")))
    (is-false (elf-has-dwarf-p binary))
    (is-false (elf-has-source-locations-p binary))
    (is (eq :completed (pipeline-stage-status binary :build)))))

(test source-form-tracking-disabled
  "sb-c:*source-location-store-source-form-p* nil is recorded in the CMMN audit log."
  (let ((case-log (cmmn-case-log (run-pipeline :source "fixtures/hello.lisp"))))
    (is (member :source-location-tracking-disabled case-log :test #'eq))))

(test build-failure-opens-exception-task
  "A compilation error transitions to BuildFailure exception, not to signing."
  (let ((result (run-pipeline :source "fixtures/bad-types.lisp")))
    (is (eq :exception (pipeline-stage-status result :build)))
    (is (cmmn-exception-task-open-p result "BuildFailure"))
    (is-false (pipeline-stage-status result :sign))))

(test cispec-labels-injected-before-signing
  "All three required org.cispec labels appear in ELF notes after label injection."
  (let ((binary (run-pipeline :source "fixtures/hello.lisp" :phase :label-injection)))
    (is (read-elf-label binary "org.cispec.application"))
    (is (read-elf-label binary "org.cispec.managed-by"))
    (is (read-elf-label binary "org.cispec.version"))
    (is (eq :completed (pipeline-stage-status binary :label-injection)))))

;;; ──────────────────────────────────────────────────────────────────
;;; signing.feature
;;; ──────────────────────────────────────────────────────────────────

(def-suite signing-suite
  :in cmmn-trusted-computing-suite
  :description "elfsign and cosign flows")

(in-suite signing-suite)

(test elfsign-embeds-note-section
  "elfsign produces a .note.signature ELF section with a valid RSA-PSS signature."
  (let* ((binary (fixture-binary "fixtures/hello.elf"))
         (signed (elfsign-binary binary)))
    (is (elf-has-note-section-p signed ".note.signature"))
    (is (rsa-pss-signature-valid-p signed))
    (is (eq :completed (pipeline-stage-status signed :sign)))))

(test cosign-attest-creates-rekor-entry
  "cosign attest produces a Rekor log entry containing the org.cispec labels."
  (let* ((binary (fixture-signed-binary))
         (result (cosign-attest binary :token (step-ca-oidc-token))))
    (is (rekor-entry-exists-p (elf-digest binary)))
    (is (rekor-payload-contains-p result "org.cispec.application"))
    (is (eq :completed (pipeline-stage-status binary :attest)))))

(test libcimatrix-gate-blocks-signing
  "Signing does not run when libcimatrix gate exits non-zero."
  (let ((binary (fixture-binary-missing-labels)))
    (is-false (run-cimatrix-gate binary))
    (is-false (elfsign-binary binary))
    (is (eq :blocked (pipeline-stage-status binary :sign)))))

(test cosign-verify-passes-on-untampered
  "cosign verify succeeds against the Rekor log for an untampered binary."
  (let ((binary (fixture-signed-attested-binary)))
    (is (cosign-verify binary))))

(test cosign-verify-fails-on-tampered
  "cosign verify fails and opens TamperDetected exception on a modified binary."
  (let* ((binary (fixture-signed-attested-binary))
         (tampered (tamper-binary binary)))
    (is-false (cosign-verify tampered))
    (is (cmmn-exception-task-open-p tampered "TamperDetected"))))

;;; ──────────────────────────────────────────────────────────────────
;;; pki.feature
;;; ──────────────────────────────────────────────────────────────────

(def-suite pki-suite
  :in cmmn-trusted-computing-suite
  :description "step-ca short-lived certificate lifecycle")

(in-suite pki-suite)

(test certificate-issued-with-short-ttl
  "step-ca issues a certificate with a 15-minute TTL matching the pipeline identity."
  (let ((cert (request-certificate :identity "cmmn-trusted-computing")))
    (is (<= (certificate-ttl cert) 900))
    (is (string= (certificate-subject cert)
                 (cispec-label "org.cispec.application")))
    (is (eq :completed (pipeline-stage-status cert :pki)))))

(test certificate-revoked-after-use
  "step-ca revocation is called and the CMMN audit log records the timestamp."
  (let* ((cert (request-certificate :identity "cmmn-trusted-computing"))
         (log  (use-and-revoke cert)))
    (is (revocation-recorded-p log (certificate-serial cert)))))

(test expired-certificate-blocks-signing
  "An expired certificate causes elfsign to exit non-zero and opens CertExpired."
  (let ((expired-cert (fixture-expired-certificate)))
    (is (certificate-expired-p expired-cert))
    (is-false (elfsign-binary (fixture-binary "fixtures/hello.elf")
                              :cert expired-cert))
    (is (cmmn-exception-task-open-p expired-cert "CertExpired"))))

(test ca-fingerprint-pinned-in-binary
  "org.cispec.pki-root label matches the step-ca root SHA-256 fingerprint."
  (let* ((binary (fixture-signed-binary))
         (label  (read-elf-label binary "org.cispec.pki-root")))
    (is (string= label (step-ca-root-fingerprint)))))

;;; ──────────────────────────────────────────────────────────────────
;;; cispec.feature
;;; ──────────────────────────────────────────────────────────────────

(def-suite cispec-suite
  :in cmmn-trusted-computing-suite
  :description "org.cispec label compliance via libcimatrix")

(in-suite cispec-suite)

(defparameter *required-labels*
  '("org.cispec.application"
    "org.cispec.managed-by"
    "org.cispec.fqdn"
    "org.cispec.service-account"
    "org.cispec.version"
    "org.cispec.pki-root"))

(test all-six-labels-present
  "libcimatrix gate exits zero when all six required labels are non-empty."
  (let ((binary (fixture-fully-labelled-binary)))
    (dolist (label *required-labels*)
      (is (read-elf-label binary label)
          (format nil "Label ~A must be present and non-empty" label)))
    (is (run-cimatrix-gate binary))))

(test missing-label-causes-gate-failure
  "libcimatrix gate exits non-zero and names the missing field."
  (let* ((binary (fixture-binary-missing-label "org.cispec.fqdn"))
         (result (run-cimatrix-gate binary)))
    (is-false result)
    (is (gate-error-names-field-p result "org.cispec.fqdn"))))

(test label-injection-is-idempotent
  "Re-running label injection with identical values produces no change."
  (let* ((binary (fixture-fully-labelled-binary))
         (digest-before (elf-digest binary))
         (_             (inject-labels binary))
         (digest-after  (elf-digest binary)))
    (declare (ignore _))
    (is (string= digest-before digest-after))
    (is (run-cimatrix-gate binary))))

(test version-label-is-semver
  "org.cispec.version matches MAJOR.MINOR.PATCH with no pre-release suffix."
  (let* ((binary  (fixture-fully-labelled-binary))
         (version (read-elf-label binary "org.cispec.version")))
    (is (cl-ppcre:scan "^\\d+\\.\\d+\\.\\d+$" version))))
