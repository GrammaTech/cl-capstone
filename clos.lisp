(defpackage :capstone/clos
  (:use :gt :cffi :static-vectors :capstone)
  (:export :version
           :capstone-engine
           :capstone-instruction
           :disasm))
(in-package :capstone/clos)
(in-readtable :curry-compose-reader-macros)
#+debug (declaim (optimize (debug 3)))

(defun version ()
  "Return the CAPSTONE version as two values MAJOR and MINOR."
  (let* ((encoded-version (cs-version 0 0))
         (major (ash encoded-version -8)))
    (values major (- encoded-version (ash major 8)))))

(defclass capstone-engine ()
  ((architecture :initarg :architecture :reader architecture :type keyword
                 :initform (required-argument :architecture))
   (mode :initarg :mode :reader mode :type keyword
         :initform (required-argument :mode))
   (handle :reader handle)))

(defmethod initialize-instance :after ((engine capstone-engine) &key)
  (with-slots (architecture mode handle) engine
    (setf handle (foreign-alloc 'cs-handle))
    (assert (eql :ok (cs-open architecture mode handle))
            (architecture mode)
            "Capstone Engine initialization with `cs-open' failed with ~S."
            (cs-strerror (cs-errno handle))))
  #+sbcl (sb-impl::finalize engine
                            (lambda ()
                              (with-slots (handle) engine
                                (cs-close handle)))))

(defmethod print-object ((obj capstone-engine) stream)
  (print-unreadable-object (obj stream :type t :identity t)
    (format stream "~a ~a" (architecture obj) (mode obj))))

(defclass capstone-instruction ()
  ((id :initarg :id :reader id :type integer)
   (address :initarg :address :reader address :type unsigned-integer)
   (size :initarg :size :reader size :type fixnum)
   (bytes :initarg :bytes :reader bytes :type '(simple-array (unsigned-byte 8)))
   (mnemonic :initarg :mnemonic :reader mnemonic :type :keyword)
   (operands :initarg :operands :reader operands :type list)))

(defmethod print-object ((obj capstone-instruction) stream)
  (print-unreadable-object (obj stream :type t)
    (format stream "~S~{~^ ~S~^,~}" (mnemonic obj) (operands obj))))

(defmethod disasm ((engine capstone-engine) (bytes vector))
  (setf bytes (make-array (length bytes)
                          :element-type '(unsigned-byte 8)
                          :initial-contents bytes))
  (nest
   (with-slots (handle) engine)
   (with-static-vector (code (length bytes)
                             :element-type '(unsigned-byte 8)
                             :initial-contents bytes))
   (with-foreign-object (instr** '(:pointer (:pointer (:struct cs-insn)))))
   (let ((count (cs-disasm (mem-ref handle 'cs-handle)
                           (static-vector-pointer code)
                           (length bytes) #x1000 0 instr**)))
     (assert (and (numberp count) (> count 0)) (code handle)
             "Disassembly failed with ~S." (cs-strerror (cs-errno handle))))
   (let ((result (make-array count))))
   (flet ((split (op-str)
            (split-sequence #\Space op-str :remove-empty-subseqs t))
          (bytes (p)
            (let ((r (make-array 16 :element-type '(unsigned-byte 8))))
              (dotimes (n 16 r)
                (setf (aref r n) (mem-aref p :uint8 n)))))))
   (dotimes (n count result))
   (let ((insn (inc-pointer (mem-ref instr** :pointer)
                            (* n (foreign-type-size
                                  '(:struct cs-insn)))))))
   (setf (aref result n))
   (make-instance 'capstone-instruction
     :id (foreign-slot-value insn '(:struct cs-insn) 'id)
     :address (foreign-slot-value insn '(:struct cs-insn) 'address)
     :size (foreign-slot-value insn '(:struct cs-insn) 'insn-size)
     :bytes (bytes (foreign-slot-value insn '(:struct cs-insn) 'bytes))
     :mnemonic (nest (make-keyword)
                     (string-upcase)
                     (foreign-string-to-lisp)
                     (foreign-slot-value insn '(:struct cs-insn) 'mnemonic))
     :operands (nest (mapcar [#'make-keyword #'string-upcase])
                     (split)
                     (foreign-string-to-lisp)
                     (foreign-slot-value insn '(:struct cs-insn) 'op-str)))))
