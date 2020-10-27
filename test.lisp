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
  (:import-from :capstone :opstring-to-tokens)
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

; push r0 = stmaldb r13!,r0 = 1110 1001 0010 1101 0000 0000 0000 0001
; ldr r0, [pc, #952] = 1110 0101 1001 1111 0000 0011 1011 1000
(deftest simple-disasm-arm ()
  (let ((engine (make-instance 'capstone-engine :architecture :arm :mode :arm)))
    (nest (is)
          (equalp '((:ANDEQ :R0 :R0 :R0)
                    (:MOV :R0 :R0))
                  (map 'list «cons #'mnemonic #'operands»
                       (disasm engine #(#x00 #x00 #x00 #x00
                                             #x00 #x00 #xa0 #xe1)))))
    (nest (is)
          (equalp '((:STMDB :SP :WBACK (:REGSET (:R0)))
                    (:LDR :R0 (:DEREF (:+ :PC 952))))
                  (map 'list «cons #'mnemonic #'operands»
                       (disasm engine #(#x01 #x00 #x2d #xe9
                                             #xb8 #x03 #x9f #xe5)))))))

; push {r0} = 1011 0100 0000 0001
; 0x3b8 rol 29 = 0x77; (29 << 7) = 0xE80; 0x77 | 0xE80 = 0xEF7
; ldr.w r0, [pc, #952] = 1111 1000 1101 1111 0000 0011 1011 1000
(deftest simple-disasm-thumb ()
  (let ((engine (make-instance 'capstone-engine :architecture :arm :mode :thumb)))
    (is (equalp '((:NOP))
                (map 'list «cons #'mnemonic #'operands»
                     (disasm engine #(#x00 #xbf)))))
    (is (equalp '((:PUSH (:REGSET (:R0)))
                  (:LDR.W :R0 (:DEREF (:+ :PC 952))))
                (map 'list «cons #'mnemonic #'operands»
                     (disasm engine #(#x01 #xb4 #xdf #xf8 #xb8 #x03)))))))

;;; X86 parsing tests
(deftest opstring-to-tokens.x86 ()
  (let ((insn (make-instance 'capstone-instruction/x86)))
    (is (equal (opstring-to-tokens insn "10") '(10)))
    (is (equal (opstring-to-tokens insn "-9") '(-9)))
    (is (equal (opstring-to-tokens insn "0x17") '(23)))
    (is (equal (opstring-to-tokens insn "[rbp + 0]") '(:|[| :RBP :+ 0 :|]|)))
    (is (equal (opstring-to-tokens insn "[rsp - 2]") '(:|[| :RSP :- 2 :|]|)))
    (is (equal (opstring-to-tokens insn "[eax + 0x10]") '(:|[| :EAX :+ 16 :|]|)))
    (is (equal (opstring-to-tokens insn "[edx - 0x21]") '(:|[| :EDX :- 33 :|]|)))
))

(deftest operands.x86.xmm ()
  (is (equal (operands (make-instance 'capstone-instruction/x86 :mnemonic :movdqa :op-str "xmm0, xmmword ptr [rax + 0x28]"))
             '(:XMM0 (:XMMWORD (:DEREF (:+ :RAX 40))))))
)

;;; When we can't figure out what the operand means,
;;; "fail soft" and turn it into a keyword.  Feel free
;;; to break or change these tests if you improve the parsing.
(deftest parse-capstone-operand.integer-bad-syntax ()
  (let ((insn (make-instance 'capstone-instruction/x86)))
    (is (equal (opstring-to-tokens insn "1A") '("1A")))
    (is (equal (opstring-to-tokens insn "-2B") '("-2B")))
    (is (equal (opstring-to-tokens insn "0x1H") '("0x1H")))
    (is (equal (opstring-to-tokens insn "-0x") '("-0x")))
))

;;; ARM parse tests
(deftest opstring-to-tokens.arm ()
  (let ((insn (make-instance 'capstone-instruction/arm)))
    (is (equal (opstring-to-tokens insn "lr") '(:LR)))
    (is (equal (opstring-to-tokens insn "r4, r5") '(:R4 :R5)))
    (is (equal (opstring-to-tokens insn "r4, [r5]") '(:R4 :|[| :R5 :|]|)))
    (is (equal (opstring-to-tokens insn "sp, #8") '(:SP 8)))
    (is (equal (opstring-to-tokens insn "r2, [sp, #8]") '(:R2 :|[| :SP 8 :|]|)))
    (is (equal (opstring-to-tokens insn "r2, [pc, #0x10]") '(:R2 :|[| :PC 16 :|]|)))
    (is (equal (opstring-to-tokens insn "r2, [pc, #-0x10]") '(:R2 :|[| :PC -16 :|]|)))
    (is (equal (opstring-to-tokens insn "r2, [r8], -r4") '(:R2 :|[| :R8 :|]| (:NEG :R4))))
))

(deftest operands.arm ()
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :bx :op-str "lr")) '(:LR)))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :cmp :op-str "r4, r5")) '(:R4 :R5)))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :ldr :op-str "r2, [r3]")) '(:R2 (:DEREF :R3))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :ldr :op-str "r2, [sp, #8]")) '(:R2 (:DEREF (:+ :SP 8)))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :ldr :op-str "r2, [pc, #x10]")) '(:R2 (:DEREF (:+ :PC 16)))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :ldr :op-str "r2, [pc, #-0x10]")) '(:R2 (:DEREF (:+ :PC -16)))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :strd :op-str "r4, [r7], -r8")) '(:R4 (:DEREF :R7) (:NEG :R8))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :push :op-str "{r4, lr}")) '((:REGSET (:R4 :LR)))))
   (is (equal (operands (make-instance 'capstone-instruction/arm :mnemonic :andeq :op-str "r7, r8, r8, lsr #11")) '(:R7 :R8 (:LSR :R8 11))))
)

(deftest operands.thumb ()
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :bx :op-str "lr")) '(:LR)))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :cmp :op-str "r4, r5")) '(:R4 :R5)))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :ldr :op-str "r2, [r3]")) '(:R2 (:DEREF :R3))))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :ldr :op-str "r2, [sp, #8]")) '(:R2 (:DEREF (:+ :SP 8)))))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :ldr :op-str "r2, [pc, #x10]")) '(:R2 (:DEREF (:+ :PC 16)))))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :ldr :op-str "r2, [pc, #-0x10]")) '(:R2 (:DEREF (:+ :PC -16)))))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :strd :op-str "r4, [r7], -r8")) '(:R4 (:DEREF :R7) (:NEG :R8))))
   (is (equal (operands (make-instance 'capstone-instruction/thumb :mnemonic :push :op-str "{r4, lr}")) '((:REGSET (:R4 :LR)))))
)

