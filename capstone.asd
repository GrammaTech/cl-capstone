(defsystem "capstone"
    :name "capstone"
    :author "GrammaTech"
    :licence "MIT"
    :description "Common Lisp FFI interface to the Capstone decompiler"
    :depends-on (:capstone/capstone)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system :protobuf)
    :in-order-to ((test-op (test-op "capstone/test"))))

(defsystem "capstone/test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the CAPSTONE package."
  :depends-on (capstone/capstone)
  :perform
  (test-op (o c) (symbol-call :capstone/test '#:test)))
