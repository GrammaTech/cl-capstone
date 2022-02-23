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
  (:use :gt :cffi :static-vectors :capstone/raw :cl-ppcre)
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
           :capstone-instruction/arm-A32
           :capstone-instruction/arm-T32
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
   (op-str :initarg :op-str :reader op-str :type string)
   (mnemonic :initarg :mnemonic :reader mnemonic :type :keyword)
   ))

(defclass capstone-instruction/x86 (capstone-instruction) ())
(defclass capstone-instruction/x86-32 (capstone-instruction/x86) ())
(defclass capstone-instruction/x86-64 (capstone-instruction/x86) ())
(defclass capstone-instruction/ppc (capstone-instruction) ())
(defclass capstone-instruction/ppc-32 (capstone-instruction/ppc) ())
(defclass capstone-instruction/ppc-64 (capstone-instruction/ppc) ())
(defclass capstone-instruction/arm (capstone-instruction) ())
(defclass capstone-instruction/arm-A64 (capstone-instruction/arm) ())
(defclass capstone-instruction/arm-A32 (capstone-instruction/arm) ())
(defclass capstone-instruction/arm-T32 (capstone-instruction/arm) ())

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
      ((:arm) 
       (case (mode engine)
         ((:arm) 'capstone-instruction/arm-A32)
         ((:thumb) 'capstone-instruction/arm-T32)))
      (t 'capstone-instruction))))

(defmethod print-object ((obj capstone-instruction) stream)
  (print-unreadable-object (obj stream :type t)
    (write (cons (mnemonic obj) (operands obj)) :stream stream)))
;    (write (cons (mnemonic obj) (cons (op-str obj) (operands obj))) :stream stream)))

(defgeneric operands (insn)
  (:documentation
  "Method for extracting the operands information from a
CAPSTONE-INSTRUCTION.  May vary with architecture."))

(defmethod operands ((insn capstone-instruction))
  (parse-operands-list insn (opstring-to-tokens insn (op-str insn))))

(defgeneric parse-operand (insn string)
  (:documentation
   "Method to convert single token from string format to token,
   specialized for the architecture.  This may include, for example,
   converting numeric values in various bases, recognizing known
   register names, etc."))

(defmethod parse-operand ((insn capstone-instruction/x86) tok)
  (let ((up (string-upcase tok)))
    (cond ((cl-ppcre:scan "^(([ER]?(AX|BX|CX|DX|SI|DI|BP|SP|IP))|AL|AH)$" up)
           (make-keyword up))
          ((cl-ppcre:scan "^XMM\\d+$" up)
           (make-keyword up))
          ((cl-ppcre:scan "^(BYTE|WORD|DWORD|QWORD|XWORD|XMMWORD|TBYTE|PTR)$" up)
           (make-keyword up))
          ((cl-ppcre:scan "^[-+]?0?x[0-9a-fA-F]+$" tok)
           (* (if (char= (elt tok 1) #\-) -1 1)
              (parse-integer tok :start (1+ (position #\x tok)) :radix 16)))
          ((cl-ppcre:scan "^[-+]?[0-9]+$" tok)
           (parse-integer tok :start 0 :radix 10))
          ((cl-ppcre:scan "^[-+]$" tok)
           (make-keyword tok))
          ((find tok '("[" "]" "{" "}") :test 'string=)
           (make-keyword tok))
          (t tok))))

(defmethod parse-operand ((insn capstone-instruction/arm) tok)
  (let ((up (string-upcase tok)))
    (cond ((cl-ppcre:scan "^#[-+]?[0-9]+$" tok)
           (parse-integer tok :start 1 :radix 10))
          ((cl-ppcre:scan "^#[-+]?0?x[0-9a-fA-F]+$" tok)
           (* (if (char= (elt tok 1) #\-) -1 1)
              (parse-integer tok :start (1+ (cl-ppcre:scan "x" tok)) :radix 16)))
          ((cl-ppcre:scan "^((R[0-9][0-9]?)|SB|IP|SP|FP|LR|PC)$" up)
           (make-keyword up))
          ((cl-ppcre:scan "^(-((R[0-9][0-9]?)|SB|IP|SP|FP|LR|PC))$" up)
           (list :NEG (make-keyword (subseq up 1))))
          ((cl-ppcre:scan "^(EQ|NE|CS|CC|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|AL)$" up)
           (make-keyword up))
          ((find up '("[" "]" "{" "}" "LSL" "LSR" "ASR" "ROR") :test 'string=)
           (make-keyword up))
          ((string= tok "!") :WBACK)
          (t tok))))

(defgeneric opstring-to-tokens (insn string)
  (:documentation
   "Method for parsing operand string to list of tokens, with distinct
methods per architecture."))

(defmethod parse-operands-list ((insn capstone-instruction) string)
  string)

(defmethod opstring-to-tokens ((insn capstone-instruction/arm) string)
  (mapcar {parse-operand insn}
          (remove "" (cl-ppcre:split "[, ]+|(\\[)|(\\])|([{}!])" string
                                     :with-registers-p t :omit-unmatched-p t)
                  :test 'string=)
  )
)

(defmethod opstring-to-tokens ((insn capstone-instruction/x86) string)
  (mapcar {parse-operand insn}
          (remove "" (cl-ppcre:split "[, ]+|(\\[)|(\\])|([{}!])" string
                                     :with-registers-p t :omit-unmatched-p t)
                  :test 'string=)))

(defgeneric parse-operands-list (insn oplist)
  (:documentation
   "Method for parsing operand list, with distinct methods per
architecture."))

(defmethod parse-operands-list ((insn capstone-instruction) oplist)
  oplist)

(defmethod parse-operands-list ((insn capstone-instruction/x86) oplist)
;  (format t "Parsing list ~S:~%" oplist)
  (let ((tok (car oplist))
        (rest (cdr oplist))
        (x86regs '(:AL :AH :AX :BX :CX :DX :SI :DI :BP :SP :IP
                   :EAX :EBX :ECX :EDX :ESI :EDI :EBP :ESP :EIP
                   :RAX :RBX :RCX :RDX :RSI :RDI :RBP :RSP :RIP))
        idx)
    (cond
     ((null oplist)
;      (format t "  Terminal case~%")
      nil)
     ((and (find (cadr oplist) '(:+ :-))
           (find tok x86regs)
           (numberp (caddr oplist)))
;      (format t "  Reg const offset case~%")
      `((,(cadr oplist)
          ,@(parse-operands-list insn (list tok))
          ,@(parse-operands-list insn (list (caddr oplist))))
        ,@(parse-operands-list insn (cdddr oplist))))
     ((and (eq tok :|[|)
           (setf idx (position :|]| rest :from-end t)))
;      (format t "  Deref case~%")
      `((:DEREF ,@(parse-operands-list insn (subseq rest 0 idx)))
        ,@(parse-operands-list insn (subseq rest (1+ idx)))))
     ((and (eq (cadr oplist) :PTR)
           (find tok '(:BYTE :WORD :DWORD :QWORD :XWORD :XMMWORD :TBYTE))
           (setf idx (position :|]| rest)))
;      (format t "  PTR case~%")
      `((,tok
         ,@(parse-operands-list insn (subseq rest 1 (1+ idx))))
        ,@(parse-operands-list insn (subseq rest (1+ idx)))))
     (t
;      (format t "  Default case~%")
      (cons tok (parse-operands-list insn rest))))))

(defmethod parse-operands-list ((insn capstone-instruction/arm) oplist)
;  (format t "Parsing list ~S:~%" oplist)
  (let ((tok (car oplist))
        (rest (cdr oplist))
        idx)
    (cond
     ((null oplist)
;      (format t "  Terminal case~%")
      nil)
     ((and (find (cadr oplist) '(:LSL :LSR :ASR :ROR)) (cddr oplist))
;      (format t "  Shift case~%")
      `((,(cadr oplist)
         ,@(parse-operands-list insn (list tok))
         ,@(parse-operands-list insn (list (caddr oplist))))
        ,@(parse-operands-list insn (cdddr oplist))))
     ((and (eq tok :|[|)
           (setf idx (position :|]| rest :from-end t)))
;      (format t "  Deref case~%")
      `((:DEREF ,@(if (> idx 1)
                      (list (cons :+ (parse-operands-list insn (subseq rest 0 idx))))
                      (parse-operands-list insn (subseq rest 0 idx))))
        ,@(parse-operands-list insn (subseq rest (1+ idx)))))
     ((and (eq tok :|{|)
           (setf idx (position :|}| rest :from-end t)))
;      (format t "  Regset case~%")
      `((:REGSET
         ,(parse-operands-list insn (subseq rest 0 idx)))
        ,@(parse-operands-list insn (subseq rest (1+ idx)))))
     (t
;      (format t "  Default case~%")
      (cons tok (parse-operands-list insn rest))))))

(defgeneric capstone-insn-to-string (insn)
  (:documentation "Convert a capstone instruction object to a string
that is suitable for use by keystone."))

(defmethod capstone-insn-to-string ((insn capstone-instruction))
  (format nil "~(~a~) ~{~a~^,~}" (mnemonic insn) (operands insn)))

(defun make-instruction (insn-class insn)
  "Create an object of class INSN-CLASS for the instruction INSN"
  (labels ((drop-trailing-bytes (l)
             (take-while [#'not #'zerop] l))
           (bytes (l)
             (make-array (length l)
                         :element-type '(unsigned-byte 8)
                         :initial-contents l))
           (char-list-to-string (l)
             (coerce (mapcar #'code-char (drop-trailing-bytes l)) 'string)))
    (make-instance insn-class
      :id (foreign-slot-value insn '(:struct cs-insn) 'id)
      :address (foreign-slot-value insn '(:struct cs-insn) 'address)
      :size (foreign-slot-value insn '(:struct cs-insn) 'insn-size)
      :bytes (nest (bytes)
                   (drop-trailing-bytes)
                   (foreign-slot-value insn '(:struct cs-insn) 'bytes))
      :mnemonic (nest (make-keyword)
                      (string-upcase)
                      (char-list-to-string)
                      (foreign-slot-value insn '(:struct cs-insn) 'mnemonic))
      :op-str (char-list-to-string
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
             (:ok (warn "Empty disassembly of ~S at ~x." code address))
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
