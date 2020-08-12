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
(defpackage :capstone/test
  (:use :gt :cffi :capstone/raw :capstone :stefil)
  (:import-from :capstone :parse-capstone-operand)
  (:export :test))
(in-package :capstone/test)
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


;;;; Parse Capstone operands tests
(deftest parse-capstone-operand-xmm ()
  (let ((parsed (capstone::parse-capstone-operands
                 "xmm0, xmmword ptr [rax + 0x28]")))
    (is (find :XMM0 parsed))
    (is (equalp '(:+ :RAX 40) (cadr (cadadr parsed))))))

(deftest parse-capstone-operand.integers ()
  (is (equal (parse-capstone-operand "10") 10))
  (is (equal (parse-capstone-operand "-9") -9))
  (is (equal (parse-capstone-operand "0x17") #x17))
  (is (equal (parse-capstone-operand "0(r1)") '(0 :r1)))
  (is (equal (parse-capstone-operand "-2(r2)") '(-2 :r2)))
  (is (equal (parse-capstone-operand "0x10(r3)") '(#x10 :r3)))
  (is (equal (parse-capstone-operand "-0x21(r4)") '(#x-21 :r4)))
  (is (equal (parse-capstone-operand "1A") :|1A|))
  (is (equal (parse-capstone-operand "-2B") :|-2B|))
  (is (equal (parse-capstone-operand "0x1H") :|0X1H|))
  (is (equal (parse-capstone-operand "-0x") :|-0X|)))
