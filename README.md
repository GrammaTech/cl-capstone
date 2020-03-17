CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `disasm` function which disassembles a
vector of bytes into a vector of instructions.  The following example
code,

```lisp
(with-static-vector (code 8 :element-type '(unsigned-byte 8) :initial-contents
                          '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
  (let ((handle (foreign-alloc 'capstone-handle))
        (instr* (foreign-alloc '(:pointer (:struct capstone-instruction)))))
    (assert (eql :ok (cs-open :x86 :64 handle)))
    (format t "Handle: ~x:~x~%" handle (mem-ref handle 'capstone-handle))
    (format t "Disassembly:~%")
    ;; NOTE: Memory fault at the location held in the memory pointed
    ;;       to by the HANDLE pointer.
    (let ((count (cs-disasm (mem-ref handle 'capstone-handle)
                            bytes 7 #x1000 0 instr*)))
      (assert (and (numberp count) (> count 0)))
      (dotimes (n count)
        (with-foreign-slots ((address mnemonic op_str)
                             (mem-aref instr* :pointer n)
                             (:struct capstone-instruction))
          (format t "~x: ~a ~a~%" address mnemonic op_str))))))
```

results in the following output.

```

```
