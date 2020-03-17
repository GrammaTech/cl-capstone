CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `disasm` function which disassembles a
vector of bytes into a vector of instructions.  The following example
code,

```lisp
(let ((handle (foreign-alloc 'capstone-handle))
      (instr* (foreign-alloc '(:pointer (:struct capstone-instruction))))
      (bytes (foreign-alloc :uint8 :count 8)))
  (assert (eql :ok (cs-open :x86 :64 handle)))
  (let ((code #(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00)))
    (dotimes (n 8) (setf (mem-aref bytes :uint8 n) (aref code n))))
  (format t "Disassembly:~%")
  (let ((count (cs-disasm handle bytes 7 #x1000 0 instr*)))
    (assert (and (numberp count) (> count 0)))
    (dotimes (n count)
      (with-foreign-slots ((address mnemonic op_str)
                           (mem-aref instr* :pointer n)
                           (:struct capstone-instruction))
        (format t "~x: ~a ~a~%" address mnemonic op_str)))))
```

results in the following output.

```

```
