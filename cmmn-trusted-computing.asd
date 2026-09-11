;;; umbrella system — empty by design (ASDF slash-subsystem requirement)
(defsystem "cmmn-trusted-computing"
  :description "BMAC lab: CMMN-modelled ELF trusted computing from Lisp codebases"
  :author "Dwight Spencer <denzuko@dapla.net>"
  :license "BSD 3-Clause"
  :version "0.1.0"
  :depends-on ())

(defsystem "cmmn-trusted-computing/core"
  :description "CMMN case, stage, and audit-log domain model"
  :depends-on ("cmmn-trusted-computing")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/core")))

(defsystem "cmmn-trusted-computing/cispec"
  :description "org.cispec label injection and libcimatrix gate integration"
  :depends-on ("cmmn-trusted-computing/core" "cl-ppcre")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/cispec")))

(defsystem "cmmn-trusted-computing/pki"
  :description "step-ca short-lived certificate lifecycle"
  :depends-on ("cmmn-trusted-computing/core" "cl-ppcre")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/pki")))

(defsystem "cmmn-trusted-computing/signing"
  :description "elfsign and cosign ELF signing and attestation"
  :depends-on ("cmmn-trusted-computing/core" "cmmn-trusted-computing/cispec")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/signing")))

(defsystem "cmmn-trusted-computing/pipeline"
  :description "Build pipeline DSL orchestrating all stages"
  :depends-on ("cmmn-trusted-computing/core"
               "cmmn-trusted-computing/cispec"
               "cmmn-trusted-computing/pki"
               "cmmn-trusted-computing/signing")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/pipeline")))

(defsystem "cmmn-trusted-computing/docs"
  :description "40ants-doc documentation renderer"
  :depends-on ("cmmn-trusted-computing/pipeline" "40ants-doc")
  :serial t
  :components ((:file "src/cmmn-trusted-computing/docs")))

(defsystem "cmmn-trusted-computing/tests"
  :description "FiveAM test suites fulfilling the BDD feature files"
  :depends-on ("cmmn-trusted-computing/pipeline"
               "fiveam"
               "sunny-side"
               "cl-ppcre")
  :serial t
  :components ((:file "t/spec")))

(defsystem "cmmn-trusted-computing/e2e"
  :description "End-to-end tests: execute signed binary, observe stdout, assert cispec output"
  :depends-on ("cmmn-trusted-computing/tests")
  :serial t
  :components ((:file "t/e2e")))
