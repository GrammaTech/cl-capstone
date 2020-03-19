CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
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
CAPSTONE/CLOS> (defparameter engine
                 (make-instance 'capstone-engine :architecture :x86 :mode :64))
ENGINE
CAPSTONE/CLOS> (disasm engine #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
#(#<CAPSTONE-INSTRUCTION (:PUSH :RBP)>
  #<CAPSTONE-INSTRUCTION (:MOV :RAX (:QWORD (:DEREF (:+ :RIP 5048))))>)
CAPSTONE/CLOS>
```
