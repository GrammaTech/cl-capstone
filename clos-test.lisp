;;;; test.lisp --- Tests for CLOS interface to the Capstone disassembler
;;;;
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
               (disasm engine #(#x90 #x90))))
    (nest (is)
          (equalp '((:PUSH :RBP)
                    (:MOV :RAX (:QWORD (:DEREF (:+ :RIP 5048))))))
          (map 'list «cons #'mnemonic #'operands»
               (disasm engine #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))))))

(deftest simple-disasm-iter ()
  (let ((engine (make-instance 'capstone-engine :architecture :x86 :mode :64)))
    (disasm-iter (instruction (engine (make-array 50 :initial-element #x90)))
      (is (eql (mnemonic instruction) :NOP)))
    (let ((counter 0)
          (disasm '((:PUSH :RBP)
                    (:MOV :RAX (:QWORD (:DEREF (:+ :RIP 5048)))))))
      (nest
       (is)
       (= 2)                            ; Check the return form.
       (disasm-iter
           (instruction (engine #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00)
                                :return-form counter))
         (incf counter)
         (is (equalp (pop disasm)
                     (cons (mnemonic instruction) (operands instruction)))))))))
