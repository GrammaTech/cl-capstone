CAPSTONE
========

Common Lisp bindings to the Capstone decompiler.
https://github.com/aquynh/capstone

This library provides the `cs-disasm` and `cs-disasm-iter` functions
which disassembles vectors of bytes.  As shown in the following
examples.

```lisp
(with-static-vector (code 8 :element-type '(unsigned-byte 8) :initial-contents
                          '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
  (let ((handle (foreign-alloc 'capstone-handle))
        (instr** (foreign-alloc '(:pointer (:pointer (:struct capstone-instruction))))))
    (assert (eql :ok (cs-open :x86 :64 handle)) (handle)
            "Failed to open Capstone engine. ~a" (cs-errno handle))
    (let ((count (cs-disasm (mem-ref handle 'capstone-handle)
                            (static-vector-pointer code)
                            7 #x1000 0 instr**)))
      (assert (and (numberp count) (> count 0)) (code handle)
              "Failed to disassemble given code. ~a" (cs-errno handle))
      (format t "Disassembly[~d]:~%" count)
      (dotimes (n count)
        (with-foreign-slots ((address mnemonic op-str)
                             (mem-aref instr** :pointer n)
                             (:struct capstone-instruction))
          (format t "0x~x: ~a ~a~%" address
                  (foreign-string-to-lisp mnemonic)
                  (foreign-string-to-lisp op-str)))))))
```

```lisp
(with-static-vector (code 8 :element-type '(unsigned-byte 8) :initial-contents
                            '(#x55 #x48 #x8b #x05 #xb8 #x13 #x00 #x00))
  (let ((handle (foreign-alloc 'capstone-handle)))
    (assert (eql :ok (cs-open arch mode handle)) (handle)
            "Failed to open Capstone engine. ~a" (cs-errno handle))
    (let ((instr* (cs-malloc handle)))
      (with-foreign-object (code* :pointer)
        (with-foreign-object (size 'size-t)
          (with-foreign-object (address :uint64)
            (setf (mem-ref code* :pointer) (static-vector-pointer code)
                  (mem-ref size 'size-t) 2
                  (mem-ref address :uint64) #x1000)
            (iter (let ((success (cs-disasm-iter (mem-ref handle 'capstone-handle)
                                                 code*
                                                 size
                                                 address
                                                 instr*)))
                    (unless success (return))
                    (with-foreign-slots ((id address mnemonic op-str)
                                         instr*
                                         (:struct capstone-instruction))
                      (format t "0x~x: ~x ~x~%"
                              address
                              (foreign-string-to-lisp mnemonic)
                              (foreign-string-to-lisp op-str)))))))))))
```
