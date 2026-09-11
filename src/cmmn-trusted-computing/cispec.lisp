(declaim (optimize (debug 0) (speed 3) (safety 1)))

(defpackage #:cmmn-trusted-computing/cispec
  (:use #:cl)
  (:export #:inject-labels
           #:run-cimatrix-gate
           #:read-elf-label
           #:gate-error-names-field-p
           #:cispec-label
           #:*cispec-config*
           #:fixture-fully-labelled-binary
           #:fixture-binary-missing-label))

(in-package #:cmmn-trusted-computing/cispec)

(defparameter *required-labels*
  '("org.cispec.application"
    "org.cispec.managed-by"
    "org.cispec.fqdn"
    "org.cispec.service-account"
    "org.cispec.version"
    "org.cispec.pki-root")
  "The six org.cispec labels every ELF binary must carry.")

(defvar *cispec-config* nil
  "Alist mapping org.cispec label names to their string values for this build.")

(defun cispec-label (name)
  "Return the configured value for org.cispec label NAME, or signal an error."
  (or (cdr (assoc name *cispec-config* :test #'string=))
      (error "org.cispec label ~A is not configured" name)))

(defun inject-labels (binary-path)
  "Inject all *required-labels* into BINARY-PATH's ELF notes section.
Skips any label whose current value in the binary already matches the config."
  (dolist (label *required-labels*)
    (let ((current (read-elf-label binary-path label))
          (target  (ignore-errors (cispec-label label))))
      (unless (and current target (string= current target))
        (inject-single-label binary-path label target)))))

(defun inject-single-label (binary-path label-name value)
  "Write LABEL-NAME=VALUE into BINARY-PATH's ELF .note.org.cispec section."
  (sb-ext:run-program
   "objcopy"
   (list "--add-section"
         (format nil ".note.org.cispec=<(echo -n '~A=~A')" label-name value)
         (namestring binary-path))
   :search t :wait t))

(defun read-elf-label (binary-path label-name)
  "Return the string value of LABEL-NAME from BINARY-PATH's ELF notes, or NIL."
  (multiple-value-bind (_ out __)
      (run-readelf binary-path)
    (declare (ignore _ __))
    (extract-label-value out label-name)))

(defun extract-label-value (readelf-output label-name)
  "Parse READELF-OUTPUT and return the value for LABEL-NAME, or NIL."
  (let ((pos (search label-name readelf-output)))
    (when pos
      (let* ((start (+ pos (length label-name) 1))
             (end   (position #\Newline readelf-output :start start)))
        (string-trim '(#\Space #\Tab) (subseq readelf-output start end))))))

(defun run-readelf (binary-path)
  "Run readelf -n on BINARY-PATH, returning (values exit stdout stderr)."
  (let* ((proc (sb-ext:run-program "readelf"
                                   (list "-n" "--wide"
                                         (namestring binary-path))
                                   :search t :wait t
                                   :output :stream :error :stream))
         (out  (drain-stream (sb-ext:process-output proc)))
         (err  (drain-stream (sb-ext:process-error  proc))))
    (values (sb-ext:process-exit-code proc) out err)))

(defun drain-stream (stream)
  "Read all characters from STREAM into a string."
  (when stream
    (with-output-to-string (s)
      (loop for c = (read-char stream nil nil)
            while c do (write-char c s)))))

(defun run-cimatrix-gate (binary-path)
  "Run libcimatrix's gate against BINARY-PATH.
Returns T when all required labels are present and non-empty, NIL otherwise."
  (multiple-value-bind (exit _ err)
      (run-subprocess "cimatrix-gate" (list "--elf" (namestring binary-path)))
    (declare (ignore _))
    (cond
      ((zerop exit) t)
      (t
       (values nil err)))))

(defun gate-error-names-field-p (gate-result field-name)
  "Return T when the error output from run-cimatrix-gate names FIELD-NAME."
  (and gate-result (search field-name gate-result)))

(defun run-subprocess (program args)
  "Run PROGRAM with ARGS, returning (values exit stdout stderr)."
  (let* ((proc (sb-ext:run-program program args
                                   :search t :wait t
                                   :output :stream :error :stream))
         (out  (drain-stream (sb-ext:process-output proc)))
         (err  (drain-stream (sb-ext:process-error  proc))))
    (values (sb-ext:process-exit-code proc) out err)))

(defun fixture-fully-labelled-binary ()
  "Return a test fixture binary carrying all six org.cispec labels."
  (pathname "fixtures/hello-labelled.elf"))

(defun fixture-binary-missing-label (label-name)
  "Return a test fixture binary missing LABEL-NAME from its ELF notes."
  (declare (ignore label-name))
  (pathname "fixtures/hello-unlabelled.elf"))
