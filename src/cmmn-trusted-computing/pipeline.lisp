(declaim (optimize (debug 0) (speed 3) (safety 1)))
#+sbcl
(when (find-symbol "*SOURCE-LOCATION-STORE-SOURCE-FORM-P*" :sb-c)
  (set (find-symbol "*SOURCE-LOCATION-STORE-SOURCE-FORM-P*" :sb-c) nil))

(defpackage #:cmmn-trusted-computing/pipeline
  (:use #:cl #:cmmn-trusted-computing/core)
  (:import-from #:cmmn-trusted-computing/cispec #:inject-labels #:run-cimatrix-gate)
  (:import-from #:cmmn-trusted-computing/signing #:elfsign-binary #:cosign-attest)
  (:import-from #:cmmn-trusted-computing/pki #:request-certificate #:revoke-certificate)
  (:export #:run-pipeline
           #:pipeline-stage-status
           #:pipeline-case-open-p))

(in-package #:cmmn-trusted-computing/pipeline)

(defparameter *sbcl-compile-flags*
  '("--noinform" "--non-interactive"
    "--eval" "(declaim (optimize (debug 0) (speed 3) (safety 1)))"
    "--eval" "#+sbcl
(when (find-symbol "*SOURCE-LOCATION-STORE-SOURCE-FORM-P*" :sb-c)
  (set (find-symbol "*SOURCE-LOCATION-STORE-SOURCE-FORM-P*" :sb-c) nil))")
  "Flags passed to every SBCL invocation in the build stage.")

(defun compile-source (source-path output-path case-obj)
  "Compile SOURCE-PATH to OUTPUT-PATH using SBCL with standard hardening flags.
Records the source-location-tracking-disabled event in CASE-OBJ."
  (record-audit-event case-obj '(:source-location-tracking-disabled))
  (let ((exit-code (sb-ext:process-exit-code
                    (sb-ext:run-program
                     "sbcl"
                     (append *sbcl-compile-flags*
                             (list "--load" (namestring source-path)
                                   "--eval"
                                   (format nil "(sb-ext:save-lisp-and-die ~S :executable t :compression t)"
                                           (namestring output-path))))
                     :search t :wait t))))
    exit-code))

(defun run-pipeline (&key source (phase :attest))
  "Run the full build pipeline for SOURCE up to PHASE.
Returns the active CMMN case."
  (let ((case-obj (make-case))
        (output   (make-pathname :name "output" :type "elf"
                                 :defaults (pathname source))))
    (setf *active-case* case-obj)
    (stage-transition case-obj :build :active)
    (let ((exit (compile-source source output case-obj)))
      (cond
        ((zerop exit)
         (stage-transition case-obj :build :completed)
         (when (member phase '(:label-injection :sign :attest :verify))
           (run-label-injection output case-obj))
         (when (member phase '(:sign :attest :verify))
           (run-signing output case-obj))
         (when (member phase '(:attest :verify))
           (run-attestation output case-obj)))
        (t
         (stage-transition case-obj :build :exception)
         (open-exception-task case-obj "BuildFailure"))))
    case-obj))

(defun run-label-injection (binary case-obj)
  "Inject org.cispec labels into BINARY and transition the CMMN stage."
  (stage-transition case-obj :label-injection :active)
  (inject-labels binary)
  (stage-transition case-obj :label-injection :completed))

(defun run-signing (binary case-obj)
  "Gate on libcimatrix, then sign with elfsign and a short-lived step-ca cert."
  (stage-transition case-obj :sign :active)
  (cond
    ((run-cimatrix-gate binary)
     (let ((cert (request-certificate :identity (read-elf-label binary "org.cispec.application"))))
       (stage-transition case-obj :pki :completed)
       (elfsign-binary binary :cert cert)
       (revoke-certificate cert)
       (stage-transition case-obj :sign :completed)))
    (t
     (stage-transition case-obj :sign :blocked))))

(defun run-attestation (binary case-obj)
  "Attest the signed binary via cosign and record in CMMN."
  (stage-transition case-obj :attest :active)
  (cosign-attest binary)
  (stage-transition case-obj :attest :completed))

(defun pipeline-stage-status (case-or-binary stage-name)
  "Return the status of STAGE-NAME in the active pipeline case."
  (declare (ignore case-or-binary))
  (when *active-case*
    (stage-status *active-case* stage-name)))

(defun pipeline-case-open-p (case-obj)
  "Return T when CASE-OBJ has no completed terminal stage and no fatal exception."
  (and (not (cmmn-exception-task-open-p case-obj "BuildFailure"))
       (not (cmmn-exception-task-open-p case-obj "TamperDetected"))))
