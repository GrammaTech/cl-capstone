(defpackage :capstone/clos-test
  (:use :gt :cffi :capstone :capstone/clos :stefil)
  (:export :test))
(in-package :capstone/clos-test)
(in-readtable :curry-compose-reader-macros)

(defsuite test)
(in-suite test)

(deftest version-returns-two-numbers ()
  (is (multiple-value-call [{every #'numberp} #'list] (version))))

(deftest simple-disasm ()
  (let ((engine (make-instance 'capstone-engine :architecture :x86 :mode :64)))
    (is (every «and [{eql :NOP} #'mnemonic] {typep _ 'capstone-instruction}»
               (disasm engine #(#x90 #x90))))))
