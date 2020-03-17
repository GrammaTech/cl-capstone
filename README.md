CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `disasm` function which disassembles a
vector of bytes into a vector of instructions.  The following example
code,

> NOTE: Currently running into a problem in that the below lisp code
> and the *seemingly* identical C code in test/test1.c are not
> behaving equivalently.  See the "NOTE" comments in each.  Lisp is
> raising
> ```
> Unhandled memory fault at #xF800BEE0.
>   [Condition of type SB-SYS:MEMORY-FAULT-ERROR]
> ```
> where #xF800BEE0 is the value stored in handle.

```lisp
(with-static-vector (code 8 :element-type '(unsigned-byte 8) :initial-contents
                            '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
  (let ((handle (foreign-alloc 'capstone-handle))
        (instr* (foreign-alloc '(:pointer (:struct capstone-instruction)))))
    (assert (eql :ok (cs-open :x86 :64 handle)) (handle)
            "Failed to open Capstone engine. ~a" (cs-errno handle))
    (let ((count (cs-disasm (mem-ref handle 'capstone-handle)
                            (static-vector-pointer code)
                            7 #x1000 0 instr*)))
      (assert (and (numberp count) (> count 0)) (code handle)
              "Failed to disassemble given code. ~a" (cs-errno handle))
      (format t "Disassembly[~d]:~%" count)
      (dotimes (n count)
        (with-foreign-slots ((address mnemonic op_str)
                             (mem-aref instr* :pointer n)
                             (:struct capstone-instruction))
          (format t "~x: ~a ~a~%" address
                  (foreign-string-to-lisp mnemonic)
                  (foreign-string-to-lisp op_str)))))))
```

results in the following output.

```

```
