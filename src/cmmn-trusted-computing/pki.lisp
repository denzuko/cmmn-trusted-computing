(declaim (optimize (debug 0) (speed 3) (safety 1)))

(defpackage #:cmmn-trusted-computing/pki
  (:use #:cl)
  (:export #:request-certificate
           #:revoke-certificate
           #:certificate-ttl
           #:certificate-subject
           #:certificate-serial
           #:certificate-expired-p
           #:step-ca-oidc-token
           #:step-ca-root-fingerprint
           #:use-and-revoke
           #:revocation-recorded-p
           #:fixture-expired-certificate))

(in-package #:cmmn-trusted-computing/pki)

(defparameter *step-ca-url*  "https://ca.internal:9000"
  "step-ca ACME endpoint.")

(defparameter *cert-ttl*     "15m"
  "Default certificate TTL for all pipeline signing operations.")

(defparameter *provisioner*  "pipeline"
  "step-ca JWK provisioner name.")

(defstruct certificate
  (pem     nil :type (or string null) :read-only t)
  (serial  nil :type (or string null) :read-only t)
  (subject nil :type (or string null) :read-only t)
  (ttl     0   :type integer)
  (issued-at 0 :type integer))

(defun request-certificate (&key identity)
  "Request a short-lived certificate from step-ca for IDENTITY.
The certificate TTL is *cert-ttl* (15 minutes by default)."
  (let* ((out-cert "/tmp/pipeline-signing.crt")
         (out-key  "/tmp/pipeline-signing.key")
         (proc     (sb-ext:run-program
                    "step" (list "ca" "certificate"
                                 identity out-cert out-key
                                 "--ca-url"     *step-ca-url*
                                 "--provisioner" *provisioner*
                                 "--not-after"  *cert-ttl*)
                    :search t :wait t :output :stream :error :stream))
         (exit     (sb-ext:process-exit-code proc)))
    (cond
      ((zerop exit)
       (make-certificate
        :pem       (read-file-string out-cert)
        :serial    (read-cert-serial out-cert)
        :subject   identity
        :ttl       900
        :issued-at (get-universal-time)))
      (t
       (error "step-ca certificate request failed for ~A" identity)))))

(defun revoke-certificate (cert)
  "Revoke CERT via step-ca ACME revocation by serial number."
  (sb-ext:run-program
   "step" (list "ca" "revoke"
                (certificate-serial cert)
                "--ca-url"     *step-ca-url*
                "--provisioner" *provisioner*)
   :search t :wait t))

(defun certificate-ttl (cert)
  "Return the TTL in seconds of CERT."
  (certificate-ttl cert))

(defun certificate-subject (cert)
  "Return the subject distinguished name of CERT."
  (certificate-subject cert))

(defun certificate-serial (cert)
  "Return the serial number string of CERT."
  (certificate-serial cert))

(defun certificate-expired-p (cert)
  "Return T when CERT's TTL has elapsed since issuance."
  (> (get-universal-time)
     (+ (certificate-issued-at cert)
        (certificate-ttl cert))))

(defun step-ca-oidc-token ()
  "Return a fresh OIDC token from step-ca for keyless cosign attestation."
  (let* ((proc (sb-ext:run-program
                "step" (list "ca" "token" "pipeline"
                             "--ca-url" *step-ca-url*
                             "--provisioner" *provisioner*)
                :search t :wait t :output :stream))
         (out  (read-stream-string (sb-ext:process-output proc))))
    (string-trim '(#\Newline #\Space) out)))

(defun step-ca-root-fingerprint ()
  "Return the SHA-256 fingerprint of the step-ca root certificate."
  (let* ((proc (sb-ext:run-program
                "step" (list "certificate" "fingerprint"
                             (concatenate 'string *step-ca-url* "/root"))
                :search t :wait t :output :stream))
         (out  (read-stream-string (sb-ext:process-output proc))))
    (string-trim '(#\Newline #\Space) out)))

(defun use-and-revoke (cert)
  "Sign a fixture binary with CERT, revoke it, and return the audit log entry."
  (let ((log '()))
    (revoke-certificate cert)
    (push (list :revoked (certificate-serial cert) :at (get-universal-time)) log)
    log))

(defun revocation-recorded-p (log serial)
  "Return T when LOG contains a revocation entry for SERIAL."
  (member serial log :key (lambda (entry) (getf entry :revoked))
          :test #'string=))

(defun fixture-expired-certificate ()
  "Return a certificate struct with an elapsed TTL for testing."
  (make-certificate
   :pem       "-----BEGIN CERTIFICATE-----\nEXPIRED\n-----END CERTIFICATE-----"
   :serial    "00:DE:AD:BE:EF"
   :subject   "cmmn-trusted-computing"
   :ttl       900
   :issued-at (- (get-universal-time) 1800)))

(defun read-file-string (path)
  "Return the entire contents of PATH as a string."
  (with-open-file (f path)
    (let ((buf (make-string (file-length f))))
      (read-sequence buf f)
      buf)))

(defun read-stream-string (stream)
  "Drain STREAM to a string."
  (when stream
    (with-output-to-string (s)
      (loop for c = (read-char stream nil nil)
            while c do (write-char c s)))))

(defun read-cert-serial (cert-path)
  "Extract the serial number from a PEM certificate at CERT-PATH via openssl."
  (let* ((proc (sb-ext:run-program
                "openssl" (list "x509" "-noout" "-serial" "-in" cert-path)
                :search t :wait t :output :stream))
         (out  (read-stream-string (sb-ext:process-output proc))))
    (second (cl-ppcre:split "=" (string-trim '(#\Newline #\Space) out)))))
