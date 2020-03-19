CAPSTONE
========

Common Lisp bindings to the Capstone disassembler (version 4).
https://github.com/aquynh/capstone

The CAPSTONE package provides raw access to the capstone C API from
Common Lisp.  Its usage to drive `cs-disasm` and `cs-diasm-iter` is
demonstrated in the `cs-disasm-original-example` and
`cs-disasm-iter-original-example` tests in test.lisp.

The CAPSTONE/CLOS package provides a more lispy interface to Capstone.
For example:

```
CAPSTONE/CLOS> (version)
4
0
CAPSTONE/CLOS> (disasm engine #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
#(#<CAPSTONE-INSTRUCTION (:PUSH :RBP)>
  #<CAPSTONE-INSTRUCTION (:MOV :RAX (:QWORD (:DEREF (:+ :RIP 5048))))>)
CAPSTONE/CLOS> (version)
4
0
CAPSTONE/CLOS> (defparameter engine
                 (make-instance 'capstone-engine :architecture :x86 :mode :64))
ENGINE
CAPSTONE/CLOS> (disasm engine #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
#(#<CAPSTONE-INSTRUCTION (:PUSH :RBP)>
  #<CAPSTONE-INSTRUCTION (:MOV :RAX (:QWORD (:DEREF (:+ :RIP 5048))))>)
CAPSTONE/CLOS> (let ((counter 0))
                 (disasm-iter (i (engine
                                  #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00)))
                   (format t "~d 0x~x ~a~{~^ ~a~^,~}~%"
                           (incf counter)
                           (address i)
                           (mnemonic i)
                           (operands i))))
1 0x0 PUSH RBP
2 0x1 MOV RAX, (QWORD (DEREF (+ RIP 5048)))
; No value
CAPSTONE/CLOS>
```

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
