(defpackage :capstone
  (:use :gt :cffi)
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
   :size
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
