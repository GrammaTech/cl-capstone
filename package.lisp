;;;; package.lisp --- Package definition for CFFI bindings to libcapstone.so
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
  (:use :common-lisp :cffi)
  (:import-from :static-vectors
                :with-static-vector
                :static-vector-pointer)
  (:export
   ;; Types
   :size-t
   :cs-handle
   ;; CS-DETAIL and slots
   :cs-detail
   :regs-read
   :regs-read-count
   :regs-write
   :regs-write-count
   :groups
   :groups-count
   :instruction-info
   :cs-x86
   :cs-arm64
   :cs-arm
   :cs-m68k
   :cs-mips
   :cs-ppc
   :cs-sparc
   :cs-sysz
   :cs-xcore
   :cs-tms320c64x
   :cs-m680x
   :cs-evm
   ;; CS-INSN struct and slots
   :cs-insn
   :id
   :address
   :insn-size
   :bytes
   :mnemonic
   :op-str
   :cs-detail
   ;; Enumerations
   :cs-error
   :cs-architecture
   :cs-mode
   :cs-option-type
   ;; Functions
   :cs-version
   :cs-support
   :cs-open
   :cs-close
   :cs-errno
   :cs-strerror
   :cs-disasm
   :cs-disasm-iter
   :cs-malloc
   :cs-free
   :cs-reg-name
   :cs-insn-name
   :cs-group-name
   :cs-reg-read
   :cs-reg--write
   :cs-op-count
   :cs-op-index))
