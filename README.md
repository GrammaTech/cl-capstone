CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `disasm` function which disassembles a
vector of bytes into a vector of instructions.  The following example
code,

```lisp
(let ((capstone (make-instance 'capstone
                   :arch :x86
                   :mode :32)))
  (describe capstone)
  (format t "Disassembly:~%")
  (doseq ((instruction (disasm bytes start)))
    (with-slots (address mnemonic opstr) instruction
      (format t "~x:~a ~a" address mnemonic opstr))))
```

results in the following output.

```

```
