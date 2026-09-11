(declaim (optimize (debug 3) (speed 1) (safety 3)))

(defpackage #:cmmn-trusted-computing/e2e
  (:use #:cl #:fiveam)
  (:import-from #:cmmn-trusted-computing/signing
                #:fixture-signed-attested-binary))

(in-package #:cmmn-trusted-computing/e2e)

(def-suite e2e-suite
  :description "Execute the signed binary and assert runtime output")

(in-suite e2e-suite)

(defun run-binary (path)
  "Execute PATH and return (values exit-code stdout)."
  (let* ((proc (sb-ext:run-program (namestring path) '()
                                   :search nil :wait t :output :stream))
         (out  (with-output-to-string (s)
                 (loop for c = (read-char (sb-ext:process-output proc) nil nil)
                       while c do (write-char c s)))))
    (values (sb-ext:process-exit-code proc) out)))

(defparameter *binary* (fixture-signed-attested-binary))

(test e2e-hello-world
  "Binary executes and emits Hello, World."
  (multiple-value-bind (exit out) (run-binary *binary*)
    (is (zerop exit))
    (is (search "Hello, World" out))))

(test e2e-cispec-application
  "Binary emits org.cispec.application."
  (multiple-value-bind (_ out) (run-binary *binary*)
    (declare (ignore _))
    (is (search "org.cispec.application" out))))

(test e2e-cispec-version-semver
  "Binary emits org.cispec.version as a semver string."
  (multiple-value-bind (_ out) (run-binary *binary*)
    (declare (ignore _))
    (is (cl-ppcre:scan "org\\.cispec\\.version: \\d+\\.\\d+\\.\\d+" out))))

(test e2e-all-six-cispec-keys
  "Binary emits all six org.cispec identity keys."
  (multiple-value-bind (_ out) (run-binary *binary*)
    (declare (ignore _))
    (dolist (key '("org.cispec.application"
                   "org.cispec.managed-by"
                   "org.cispec.fqdn"
                   "org.cispec.service-account"
                   "org.cispec.version"
                   "org.cispec.pki-root"))
      (is (search key out)
          (format nil "stdout must contain ~A" key)))))

(test e2e-obfuscated-binary-executes
  "Binary compiled with debug 0 executes and produces correct output."
  (multiple-value-bind (exit out) (run-binary *binary*)
    (is (zerop exit))
    (is (search "Hello, World" out))
    (is (search "org.cispec.application" out))))
