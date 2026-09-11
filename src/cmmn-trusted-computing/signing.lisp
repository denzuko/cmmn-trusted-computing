(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)

(defpackage #:cmmn-trusted-computing/signing
  (:use #:cl)
  (:export #:elfsign-binary
           #:cosign-attest
           #:cosign-verify
           #:elf-has-note-section-p
           #:elf-has-dwarf-p
           #:elf-has-source-locations-p
           #:elf-digest
           #:rekor-entry-exists-p
           #:rekor-payload-contains-p
           #:rsa-pss-signature-valid-p
           #:tamper-binary
           #:fixture-binary
           #:fixture-signed-binary
           #:fixture-signed-attested-binary
           #:fixture-binary-missing-labels
           #:read-elf-label))

(in-package #:cmmn-trusted-computing/signing)

(defun run-subprocess (program args &key input)
  "Run PROGRAM with ARGS, returning (values exit-code stdout stderr)."
  (let* ((proc (sb-ext:run-program program args
                                   :search t :wait t
                                   :input  (when input :stream)
                                   :output :stream
                                   :error  :stream))
         (out  (read-process-output (sb-ext:process-output proc)))
         (err  (read-process-output (sb-ext:process-error  proc))))
    (values (sb-ext:process-exit-code proc) out err)))

(defun read-process-output (stream)
  "Drain STREAM to a string."
  (when stream
    (with-output-to-string (s)
      (loop for c = (read-char stream nil nil)
            while c do (write-char c s)))))

(defun elfsign-binary (binary-path &key cert)
  "Sign BINARY-PATH with elfsign, embedding the signature in .note.signature.
CERT is a pathname to the signing certificate; uses the default cert store when absent."
  (let ((args (list "--sign" (namestring binary-path))))
    (when cert
      (setf args (list* "--cert" (namestring cert) args)))
    (multiple-value-bind (exit _ err)
        (run-subprocess "elfsign" args)
      (declare (ignore _))
      (cond
        ((zerop exit) binary-path)
        (t
         (warn "elfsign failed: ~A" err)
         nil)))))

(defun cosign-attest (binary-path &key token)
  "Attest BINARY-PATH via cosign keyless flow using TOKEN as the OIDC token.
Returns the Rekor log entry on success, NIL on failure."
  (let ((args (list "attest"
                    "--predicate" (generate-predicate binary-path)
                    "--type"      "custom"
                    (namestring binary-path))))
    (when token
      (setf args (list* "--identity-token" token args)))
    (multiple-value-bind (exit out _)
        (run-subprocess "cosign" args)
      (declare (ignore _))
      (when (zerop exit) out))))

(defun cosign-verify (binary-path)
  "Verify BINARY-PATH against the Rekor transparency log.
Returns T on success, NIL on failure."
  (multiple-value-bind (exit _ __) 
      (run-subprocess "cosign" (list "verify" "--rekor-url" *rekor-url*
                                     (namestring binary-path)))
    (declare (ignore _ __))
    (zerop exit)))

(defparameter *rekor-url* "https://rekor.sigstore.dev"
  "Rekor transparency log endpoint.")

(defun generate-predicate (binary-path)
  "Write a JSON predicate file for BINARY-PATH containing its org.cispec labels."
  (let ((pred-path (make-pathname :name "predicate" :type "json"
                                  :defaults binary-path)))
    (with-open-file (out pred-path :direction :output :if-exists :supersede)
      (format out "{~%  \"application\": ~S,~%  \"digest\": ~S~%}"
              (read-elf-label binary-path "org.cispec.application")
              (elf-digest binary-path)))
    (namestring pred-path)))

(defun elf-digest (binary-path)
  "Return the SHA-256 hex digest of BINARY-PATH."
  (multiple-value-bind (_ out __)
      (run-subprocess "sha256sum" (list (namestring binary-path)))
    (declare (ignore _ __))
    (subseq out 0 64)))

(defun elf-has-note-section-p (binary-path section-name)
  "Return T when BINARY-PATH contains an ELF section named SECTION-NAME."
  (multiple-value-bind (_ out __)
      (run-subprocess "readelf" (list "-S" "--wide" (namestring binary-path)))
    (declare (ignore _ __))
    (search section-name out)))

(defun elf-has-dwarf-p (binary-path)
  "Return T when BINARY-PATH contains any DWARF debug section."
  (elf-has-note-section-p binary-path ".debug_"))

(defun elf-has-source-locations-p (binary-path)
  "Return T when BINARY-PATH contains SBCL source location data."
  (elf-has-note-section-p binary-path ".sbcl.source"))

(defun read-elf-label (binary-path label-name)
  "Return the string value of LABEL-NAME from BINARY-PATH's ELF notes, or NIL."
  (multiple-value-bind (_ out __)
      (run-subprocess "readelf" (list "-n" (namestring binary-path)))
    (declare (ignore _ __))
    (let ((pos (search label-name out)))
      (when pos
        (let* ((start (+ pos (length label-name) 2))
               (end   (position #\Newline out :start start)))
          (string-trim '(#\Space #\Tab) (subseq out start end)))))))

(defun rsa-pss-signature-valid-p (binary-path)
  "Return T when the .note.signature section in BINARY-PATH verifies against
the embedded public key."
  (multiple-value-bind (exit _ __)
      (run-subprocess "elfsign" (list "--verify" (namestring binary-path)))
    (declare (ignore _ __))
    (zerop exit)))

(defun rekor-entry-exists-p (digest)
  "Return T when a Rekor log entry for DIGEST exists."
  (multiple-value-bind (exit _ __)
      (run-subprocess "rekor-cli"
                      (list "search" "--sha" digest "--url" *rekor-url*))
    (declare (ignore _ __))
    (zerop exit)))

(defun rekor-payload-contains-p (payload key)
  "Return T when PAYLOAD string contains KEY."
  (and payload (search key payload)))

(defun tamper-binary (binary-path)
  "Return a copy of BINARY-PATH with one byte modified at offset 4096."
  (let ((tampered (make-pathname :name (concatenate 'string
                                                    (pathname-name binary-path)
                                                    "-tampered")
                                 :defaults binary-path)))
    (uiop:copy-file binary-path tampered)
    (with-open-file (f tampered :direction :io
                                :element-type '(unsigned-byte 8)
                                :if-exists :overwrite)
      (file-position f 4096)
      (write-byte (logxor (read-byte f) #xFF) f))
    tampered))

(defun fixture-binary (path)
  "Return the pathname PATH as a fixture binary."
  (pathname path))

(defun fixture-signed-binary ()
  "Return a pre-built signed fixture binary for testing."
  (pathname "fixtures/hello-signed.elf"))

(defun fixture-signed-attested-binary ()
  "Return a pre-built signed-and-attested fixture binary for testing."
  (pathname "fixtures/hello-attested.elf"))

(defun fixture-binary-missing-labels ()
  "Return a fixture binary whose org.cispec labels are absent."
  (pathname "fixtures/hello-unlabelled.elf"))
