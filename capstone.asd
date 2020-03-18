(eval-when (:load-toplevel :execute)
  (operate 'load-op 'trivial-features)
  (operate 'load-op 'cffi-grovel))

(use-package 'cffi-grovel)

(defsystem "capstone"
    :name "capstone"
    :author "GrammaTech"
    :licence "MIT"
    :description "Common Lisp FFI interface to the Capstone decompiler"
    :depends-on (:gt :cffi :static-vectors)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system :cffi-grovel)
    :components ((:file "package")
                 (:grovel-file "grovel")
                 (:file "capstone"))
    :in-order-to ((test-op (test-op "capstone/test"))))

(defsystem "capstone/test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the CAPSTONE package."
  :depends-on (capstone/capstone)
  :perform
  (test-op (o c) (symbol-call :capstone/test '#:test)))
