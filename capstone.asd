;;;; Copyright (C) 2020 GrammaTech, Inc.
;;;;
;;;; This code is licensed under the MIT license. See the LICENSE file
;;;; in the project root for license terms.
;;;;
;;;; This project is sponsored by the Office of Naval Research, One
;;;; Liberty Center, 875 N. Randolph Street, Arlington, VA 22203 under
;;;; contract # N68335-17-C-0700.  The content of the information does
;;;; not necessarily reflect the position or policy of the Government
;;;; and no official endorsement should be inferred.
(eval-when (:load-toplevel :execute)
  (operate 'load-op 'trivial-features)
  (operate 'load-op 'cffi-grovel))

(use-package 'cffi-grovel)

(defsystem "capstone"
    :name "capstone"
    :author "GrammaTech"
    :licence "MIT"
    :description "Raw Common Lisp FFI interface to the Capstone decompiler"
    :depends-on (:gt :cffi :static-vectors)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system :cffi-grovel)
    :components ((:file "package")
                 (:cffi-grovel-file "grovel")
                 (:file "capstone"))
    :in-order-to ((test-op (test-op "capstone/test"))))

(defsystem "capstone/test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the CAPSTONE package."
  :perform
  (test-op (o c) (symbol-call :capstone/test '#:test)))

(defsystem "capstone/clos"
  :author "GrammaTech"
  :licence "MIT"
  :description "Common Lisp CLOS interface to the Capstone decompiler"
  :perform
  (test-op (o c) (symbol-call :capstone/clos-test '#:test)))

(defsystem "capstone/clos-test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the CAPSTONE/CLOS package."
  :perform
  (test-op (o c) (symbol-call :capstone/clos-test '#:test)))
