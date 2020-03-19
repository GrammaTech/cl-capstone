CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `cs-disasm` and `cs-disasm-iter` functions
which disassembles vectors of bytes.  As shown in the following
examples.

```lisp
(defun run-cs-disasm (&optional (arch :x86) (mode :64)
                        (bytes '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00)))
  (with-static-vector (code (length bytes) :element-type '(unsigned-byte 8)
                            :initial-contents bytes)
    (with-foreign-object (handle 'cs-handle)
      (with-foreign-object (instr** '(:pointer (:pointer (:struct cs-insn))))
        (assert (eql :ok (cs-open arch mode handle)) (handle)
                "Failed to open Capstone engine. ~a" (cs-errno handle))
        (let ((count (cs-disasm (mem-ref handle 'cs-handle)
                                (static-vector-pointer code)
                                (length bytes) #x1000 0 instr**)))
          (assert (and (numberp count) (> count 0)) (code handle)
                  "Failed to disassemble given code. ~a" (cs-errno handle))
          (format t "Disassembly[~d]:~%" count)
          (dotimes (n count)
            (with-foreign-slots
                ((address mnemonic op-str)
                 (inc-pointer (mem-ref instr** :pointer)
                              (* n (foreign-type-size '(:struct cs-insn))))
                 (:struct cs-insn))
              (format t "0x~x: ~a ~a~%" address
                      (foreign-string-to-lisp mnemonic)
                      (foreign-string-to-lisp op-str)))))))))
```

```lisp
(defun run-cs-disasm-iter (&optional (arch :x86) (mode :64)
                             (bytes '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00)))
  (with-static-vector (code (length bytes)
                            :element-type '(unsigned-byte 8)
                            :initial-contents bytes)
    (let ((handle (foreign-alloc 'cs-handle)))
      (assert (eql :ok (cs-open arch mode handle)) (handle)
              "Failed to open Capstone engine. ~a" (cs-errno handle))
      (let ((instr* (cs-malloc handle)))
        (with-foreign-object (code* :pointer)
          (with-foreign-object (size 'size-t)
            (with-foreign-object (address :uint64)
              (setf (mem-ref code* :pointer) (static-vector-pointer code)
                    (mem-ref size 'size-t) (length bytes)
                    (mem-ref address :uint64) #x1000)
              (iter (unless (cs-disasm-iter (mem-ref handle 'cs-handle)
                                            code*
                                            size
                                            address
                                            instr*) (return))
                    (with-foreign-slots ((id address mnemonic op-str) instr*
                                         (:struct cs-insn))
                      (format t "0x~x: ~x ~x~%"
                              address
                              (foreign-string-to-lisp mnemonic)
                              (foreign-string-to-lisp op-str)))))))))))
```

which both output the following.

```
0x1000: push rbp
0x1001: mov rax, qword ptr [rip + 0x13b8]
```
