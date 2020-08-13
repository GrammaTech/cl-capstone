;;;; clos.lisp --- CLOS interface to the Capstone disassembler
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
(defpackage :capstone
  (:use :gt :cffi :static-vectors :capstone/raw)
  (:export :version
           :capstone
           :disassembly
           :mnemonic
           ;; CAPSTONE-ENGINE class and accessors
           :capstone-engine
           :architecture
           :mode
           ;; CAPSTONE-INSTRUCTION class, subclasses, and accessors
           :capstone-instruction
           :capstone-instruction/x86
           :capstone-instruction/x86-32
           :capstone-instruction/x86-64
           :capstone-instruction/ppc
           :capstone-instruction/ppc-32
           :capstone-instruction/ppc-64
           :capstone-instruction/arm
           :id
           :address
           :bytes
           :mnemonic
           :operands
           ;; Disassembly functionality
           :disasm
           :disasm-iter))

(in-package :capstone)
(in-readtable :curry-compose-reader-macros)
#+debug (declaim (optimize (debug 3)))

(defun version ()
  "Return the CAPSTONE version as two values MAJOR and MINOR."
  (let* ((encoded-version (cs-version 0 0))
         (major (ash encoded-version -8)))
    (values major (- encoded-version (ash major 8)))))

(define-condition capstone (error)
  ((code :initarg :code :initform nil :reader code)
   (strerr :initarg :strerr :initform nil :reader strerr))
  (:report (lambda (condition stream)
             (format stream "Capstone error ~S." (strerr condition))))
  (:documentation "Capstone error."))

(define-condition disassembly (capstone)
  ((bytes :initarg :bytes :initform nil :reader bytes))
  (:report (lambda (condition stream)
             (format stream "Disassembly error ~S on ~S."
                     (strerr condition) (bytes condition))))
  (:documentation "Capstone disassembly error."))

(defclass capstone-engine ()
  ((architecture :initarg :architecture :reader architecture :type keyword
                 :initform (required-argument :architecture))
   (mode :initarg :mode :reader mode :type (or keyword list)
         :initform (required-argument :mode))
   (handle)))

(defmethod initialize-instance :after ((engine capstone-engine) &key)
  (with-slots (architecture mode handle) engine
    (setf handle (foreign-alloc 'cs-handle))
    (let* ((actual-mode (if (listp mode)
                           (reduce #'logior mode
                                   :key {foreign-enum-value 'cs-mode}
                                   :initial-value 0)
                           mode))
           (errno (cs-open architecture actual-mode handle)))
        (unless (eql :ok errno)
          (error (make-condition 'capstone
                                 :code errno
                                 :strerr (cs-strerror errno)))))
    #+sbcl (sb-impl::finalize engine
                              (lambda ()
                                (with-slots (handle) engine
                                  (cs-close handle))))))

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

(defclass capstone-instruction/x86 (capstone-instruction) ())
(defclass capstone-instruction/x86-32 (capstone-instruction/x86) ())
(defclass capstone-instruction/x86-64 (capstone-instruction/x86) ())
(defclass capstone-instruction/ppc (capstone-instruction) ())
(defclass capstone-instruction/ppc-32 (capstone-instruction/ppc) ())
(defclass capstone-instruction/ppc-64 (capstone-instruction/ppc) ())
(defclass capstone-instruction/arm (capstone-instruction) ())

(defgeneric capstone-instruction-class (engine)
  (:documentation
  "The name of the subclass of CAPSTONE-INSTRUCTION for the
particular architecture, or CAPSTONE-INSTRUCTION if there is such
proper subclass.")
  (:method ((engine capstone-engine))
    (case (architecture engine)
      ((:x86)
       (case (mode engine)
         ((:64) 'capstone-instruction/x86-64)
         ((:32) 'capstone-instruction/x86-32)
         (t 'capstone-instruction/x86)))
      ((:ppc)
       (let ((mode (mode engine)))
         (unless (listp mode) (setf mode (list mode)))
         (cond
           ((member :64 mode) 'capstone-instruction/ppc-64)
           ((member :32 mode) 'capstone-instruction/ppc-32)
           (t 'capstone-instruction/ppc))))
      ((:arm) 'capstone-instruction/arm)
      (t 'capstone-instruction))))

(defmethod print-object ((obj capstone-instruction) stream)
  (print-unreadable-object (obj stream :type t)
    (write (cons (mnemonic obj) (operands obj)) :stream stream)))

(defun parse-register (str)
  "Recognize (r<n>) and parse as a :r<n> keyword.  Otherwise, NIL"
  (setf str (string-upcase str))
  (let ((len (length str)))
    (if (and (> len 2)
             (string= str "(R" :end1 2)
             (char= (elt str (1- len)) #\)))
        (make-keyword (subseq str 1 (1- len)))
        nil)))

;;; Taken from a patch by _death.
;;;
;;; The fallback behavior of decoding an operand is to just
;;; turn it into a keyword.  In general, users should not
;;; decode these, but instead augment operand parsing so
;;; those cases are covered.
(defun parse-capstone-operand (string &aux p)
  (declare (optimize (speed 3))
           (type string string))
  (flet ((%decode-with-int (start radix neg?)
           (multiple-value-bind (i pos)
               (parse-integer string :radix radix
                                     :start start
                                     :junk-allowed t)
             (if (null i)
                 (make-keyword (string-upcase string))
                 (let ((i (if neg? (- i) i))
                       (rest (trim-whitespace (subseq string pos))))
                   (if (string= rest "")
                       i
                       (let ((reg (parse-register rest)))
                         (if reg (list i reg)
                             (make-keyword (string-upcase string))))))))))
    (cond ((starts-with-subseq "0x" string)
           (%decode-with-int 2 16 nil))
          ((starts-with-subseq "-0x" string)
           (%decode-with-int 3 16 t))
          ((and (starts-with-subseq "-" string)
                (> (length string) 1)
                (digit-char-p (elt string 1)))
           (%decode-with-int 1 10 t))
          ((digit-char-p (elt string 0))
           (%decode-with-int 0 10 nil))
          ((starts-with-subseq "[" string)
           (list :deref (parse-capstone-operand (subseq string 1 (1- (length string))))))
          ((starts-with-subseq "byte ptr " string)
           (list :byte (parse-capstone-operand (subseq string 9))))
          ((starts-with-subseq "word ptr " string)
           (list :word (parse-capstone-operand (subseq string 9))))
          ((starts-with-subseq "dword ptr " string)
           (list :dword (parse-capstone-operand (subseq string 10))))
          ((starts-with-subseq "qword ptr " string)
           (list :qword (parse-capstone-operand (subseq string 10))))
          ((starts-with-subseq "xword ptr " string)
           (list :qword (parse-capstone-operand (subseq string 10))))
          ((starts-with-subseq "xmmword ptr " string)
           (list :qword (parse-capstone-operand (subseq string 12))))
          ((starts-with-subseq "tbyte ptr " string)
           (list :tbyte (parse-capstone-operand (subseq string 10))))
          ((starts-with-subseq "cs:" string)
           (list (list :seg :cs) (parse-capstone-operand (subseq string 3))))
          ((starts-with-subseq "ds:" string)
           (list (list :seg :ds) (parse-capstone-operand (subseq string 3))))
          ((starts-with-subseq "es:" string)
           (list (list :seg :es) (parse-capstone-operand (subseq string 3))))
          ((starts-with-subseq "fs:" string)
           (list (list :seg :fs) (parse-capstone-operand (subseq string 3))))
          ((starts-with-subseq "gs:" string)
           (list (list :seg :gs) (parse-capstone-operand (subseq string 3))))
          ((setq p (search " + " string))
           (list :+
                 (parse-capstone-operand (subseq string 0 p))
                 (parse-capstone-operand (subseq string (+ p 3)))))
          ((setq p (search " - " string))
           (list :-
                 (parse-capstone-operand (subseq string 0 p))
                 (parse-capstone-operand (subseq string (+ p 3)))))
          ((setq p (search "*" string))
           (list :*
                 (parse-capstone-operand (subseq string 0 p))
                 (parse-capstone-operand (subseq string (1+ p)))))
;;          ((every #'digit-char-p string)
;;           (parse-integer string))
          (t
           (make-keyword (string-upcase string))))))

;;; Adapted from a patch by _death.
(defun parse-capstone-operands (operands)
  (if (equal operands "")
      nil
      (mapcar (lambda (s) (parse-capstone-operand (trim-whitespace s)))
              (split-sequence #\, operands))))

(defgeneric capstone-insn-to-string (insn)
  (:documentation "Convert a capstone instruction object to a string
that is suitable for use by keystone."))

(defmethod capstone-insn-to-string ((insn capstone-instruction))
  (format nil "~(~a~) ~{~a~^,~}" (mnemonic insn) (operands insn)))

(defun make-instruction (insn-class insn)
  "Create an object of class INSN-CLASS for the instruction INSN"
  (flet ((bytes (p)
           (let ((r (make-array 16 :element-type '(unsigned-byte 8))))
             (dotimes (n 16 r)
               (setf (aref r n) (mem-aref p :uint8 n))))))
    (make-instance insn-class
      :id (foreign-slot-value insn '(:struct cs-insn) 'id)
      :address (foreign-slot-value insn '(:struct cs-insn) 'address)
      :size (foreign-slot-value insn '(:struct cs-insn) 'insn-size)
      :bytes (bytes (foreign-slot-value insn '(:struct cs-insn) 'bytes))
      :mnemonic (nest (make-keyword)
                      (string-upcase)
                      (foreign-string-to-lisp)
                      (foreign-slot-value insn '(:struct cs-insn) 'mnemonic))
      :operands (nest (parse-capstone-operands)
                      (foreign-string-to-lisp)
                      (foreign-slot-value insn '(:struct cs-insn) 'op-str)))))

(defgeneric disasm (engine bytes &key address count)
  (:documentation
   "Disassemble BYTES with ENGINE using starting address ADDRESS.
Optional argument COUNT may be supplied to limit the number of
instructions disassembled.")
  (:method ((engine capstone-engine) (bytes vector)
            &key (address 0) (count 0 count-p)
            &aux (instruction-class
                  (capstone-instruction-class engine)))
    (when count-p
      (check-type count integer)
      (when (zerop count) (return-from disasm)))
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
                             (length bytes) address 0 instr**)))
       (unless (and (numberp count) (> count 0))
         (let ((errno (cs-errno handle)))
           (case errno
             (:ok (warn "Empty disassembly of ~S." code))
             (t (error (make-condition 'disassembly
                                       :code errno
                                       :strerr (cs-strerror errno)
                                       :bytes code)))))))
     (let ((result (make-array count))))
     (dotimes (n count result))
     (let ((insn (inc-pointer (mem-ref instr** :pointer)
                              (* n (foreign-type-size
                                    '(:struct cs-insn)))))))
     (setf (aref result n))
     (make-instruction instruction-class insn))))

(defmacro disasm-iter
    ((var (engine bytes &key (address 0) (return-form '(values)))) &body body)
  "Use ENGINE to disassemble BYTES one instructions at a time.
Bind each instruction to VAR when executing BODY.  Optional argument
ADDRESS may be used to set the starting ADDRESS during disassembly."
  (with-gensyms (code code* size* address* instr* insn-class)
    (once-only ((full-bytes bytes) (eng engine))
      `(with-slots (handle) ,eng
         (with-static-vector (,code (length ,full-bytes)
                                    :element-type '(unsigned-byte 8)
                                    :initial-contents ,full-bytes)
           (let ((,instr* (cs-malloc handle))
                 (,insn-class (capstone-instruction-class ,eng)))
             (unwind-protect
                  (with-foreign-object (,code* :pointer)
                    (with-foreign-object (,size* 'size-t)
                      (with-foreign-object (,address* :uint64)
                        (setf (mem-ref ,code* :pointer)
                              (static-vector-pointer ,code)
                              (mem-ref ,size* 'size-t) (length ,full-bytes)
                              (mem-ref ,address* :uint64) ,address)
                        (loop (unless (cs-disasm-iter
                                       (mem-ref handle 'cs-handle)
                                       ,code* ,size* ,address* ,instr*)
                                (return ,return-form))
                           (let ((,var (make-instruction ,insn-class ,instr*)))
                             ,@body)))))
               (cs-free ,instr* 1))))))))
