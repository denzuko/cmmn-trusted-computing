(declaim (optimize (debug 0) (speed 3) (safety 1)))
(setf sb-c:*source-location-store-source-form-p* nil)

(defpackage #:cmmn-trusted-computing/core
  (:use #:cl)
  (:export #:make-case
           #:case-id
           #:case-stages
           #:case-audit-log
           #:open-exception-task
           #:cmmn-exception-task-open-p
           #:cmmn-case-log
           #:stage-transition
           #:stage-status
           #:record-audit-event
           #:*active-case*))

(in-package #:cmmn-trusted-computing/core)

(defvar *active-case* nil
  "The currently active CMMN case for the build pipeline run.")

(defstruct case-stage
  (name    nil :type symbol :read-only t)
  (status  :initial :type (member :initial :active :completed :blocked :exception))
  (events  '() :type list))

(defstruct cmmn-case
  (id        (make-uuid) :type string :read-only t)
  (stages    (make-stage-map) :type hash-table)
  (audit-log '() :type list)
  (exceptions '() :type list))

(defun make-uuid ()
  "Return a pseudo-random UUID string."
  (format nil "~8,'0X-~4,'0X-~4,'0X-~4,'0X-~12,'0X"
          (random #xFFFFFFFF) (random #xFFFF)
          (logior #x4000 (random #x0FFF))
          (logior #x8000 (logand #x3FFF (random #xFFFF)))
          (random #xFFFFFFFFFFFF)))

(defun make-stage-map ()
  "Return an empty hash-table for stage tracking."
  (make-hash-table :test #'eq))

(defun make-case ()
  "Return a new CMMN case with the standard pipeline stages initialised."
  (let ((c (make-cmmn-case)))
    (dolist (stage '(:build :label-injection :pki :sign :attest :verify))
      (setf (gethash stage (cmmn-case-stages c))
            (make-case-stage :name stage)))
    c))

(defun stage-transition (case-obj stage-name new-status)
  "Transition STAGE-NAME in CASE-OBJ to NEW-STATUS, recording the event."
  (let ((stage (gethash stage-name (cmmn-case-stages case-obj))))
    (when stage
      (setf (case-stage-status stage) new-status)
      (record-audit-event case-obj
                          (list :stage stage-name
                                :transition new-status
                                :at (get-universal-time))))))

(defun stage-status (case-obj stage-name)
  "Return the current status of STAGE-NAME in CASE-OBJ, or NIL if absent."
  (let ((stage (gethash stage-name (cmmn-case-stages case-obj))))
    (when stage (case-stage-status stage))))

(defun open-exception-task (case-obj task-name)
  "Add TASK-NAME to the exception list of CASE-OBJ."
  (push task-name (cmmn-case-exceptions case-obj))
  (record-audit-event case-obj
                      (list :exception task-name :at (get-universal-time))))

(defun cmmn-exception-task-open-p (case-obj task-name)
  "Return T when TASK-NAME is present in the exception list of CASE-OBJ."
  (member task-name (cmmn-case-exceptions case-obj) :test #'string=))

(defun cmmn-case-log (case-obj)
  "Return the audit log of CASE-OBJ as a list of event plists."
  (cmmn-case-audit-log case-obj))

(defun record-audit-event (case-obj event)
  "Append EVENT to the audit log of CASE-OBJ."
  (setf (cmmn-case-audit-log case-obj)
        (append (cmmn-case-audit-log case-obj) (list event))))

(defparameter *identity*
  '(("org.cispec.application"   . "cmmn-trusted-computing")
    ("org.cispec.managed-by"    . "consfigurator")
    ("org.cispec.fqdn"          . "cmmn.dapla.net")
    ("org.cispec.service-account" . "cmmn")
    ("org.cispec.version"       . "0.1.0")
    ("org.cispec.pki-root"      . ""))
  "Runtime org.cispec identity objects emitted by the binary on execution.")

(defun emit-identity ()
  "Print all org.cispec identity objects to stdout."
  (dolist (pair *identity*)
    (format t "~A: ~A~%" (car pair) (cdr pair))))

(defun main ()
  "Binary entry point: emit org.cispec identity then hello world output."
  (emit-identity)
  (format t "Hello, World~%")
  (sb-ext:exit :code 0))
