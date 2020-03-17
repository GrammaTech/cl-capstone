(defpackage :capstone
  (:use :gt :cffi)
  (:import-from :static-vectors :with-static-vector)
  (:export :disasm
           ;; Fields of the instruction object.
           :address :mnemonic :opstr))
(in-package :capstone)
(in-readtable :curry-compose-reader-macros)

(cffi:define-foreign-library libcapstone
  (t (:default "libcapstone")))
(use-foreign-library libcapstone)


;;;; CFFI definitions.
(defctype size-t :unsigned-int)

(defctype capstone-handle size-t
  "Capstone engine handle.")

(defcstruct capstone-instruction
  "Detail information of disassembled instruction."
  (id :int)
  (address :uint64)
  (size :uint64)
  (bytes :uint8 :count 16)
  (mnemonic :char :count 32)            ; CS_MNEMONIC_SIZE
  (op_str :char :count 160)
  (details :pointer))

(defcenum capstone-error
  (:OK 0)    ; No error: everything was fine
  :MEM       ; Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
  :ARCH      ; Unsupported architecture: cs_open()
  :HANDLE    ; Invalid handle: cs_op_count(), cs_op_index()
  :CSH       ; Invalid csh argument: cs_close(), cs_errno(), cs_option()
  :MODE      ; Invalid/unsupported mode: cs_open()
  :OPTION    ; Invalid/unsupported option: cs_option()
  :DETAIL    ; Information is unavailable because detail option is OFF
  :MEMSETUP  ; Dynamic memory management uninitialized (see CS_OPT_MEM)
  :VERSION   ; Unsupported version (bindings)
  :DIET      ; Access irrelevant data in "diet" engine
  :SKIPDATA  ; Access irrelevant data for "data" instruction in SKIPDATA mode
  :X86_ATT   ; X86 AT&T syntax is unsupported (opt-out at compile time)
  :X86_INTEL ; X86 Intel syntax is unsupported (opt-out at compile time)
  :X86_MASM) ; X86 Intel syntax is unsupported (opt-out at compile time)

(defcenum capstone-architecture
  (:ARM 0)               ; ARM architecture (including Thumb, Thumb-2)
  :ARM64                 ; ARM-64, also called AArch64
  :MIPS                  ; Mips architecture
  :X86                   ; X86 architecture (including x86 & x86-64)
  :PPC                   ; PowerPC architecture
  :SPARC                 ; Sparc architecture
  :SYSZ                  ; SystemZ architecture
  :XCORE                 ; XCore architecture
  :M68K                  ; 68K architecture
  :TMS320C64X            ; TMS320C64x architecture
  :M680X                 ; 680X architecture
  :EVM                   ; Ethereum architecture
  :MAX
  (:ALL #xFFFF))         ; All architectures - for cs_support()

(defcenum capstone-mode
  (:LITTLE_ENDIAN 0)           ; little-endian mode (default mode)
  (:ARM 0)                     ; 32-bit ARM
  (:16 #.(ash 1 1))             ; 16-bit mode (X86)
  (:32 #.(ash 1 2))             ; 32-bit mode (X86)
  (:64 #.(ash 1 3))             ; 64-bit mode (X86, PPC)
  (:THUMB #.(ash 1 4))          ; ARM's Thumb mode, including Thumb-2
  (:MCLASS #.(ash 1 5))         ; ARM's Cortex-M series
  (:V8 #.(ash 1 6))             ; ARMv8 A32 encodings for ARM
  (:MICRO #.(ash 1 4))          ; MicroMips mode (MIPS)
  (:MIPS3 #.(ash 1 5))          ; Mips III ISA
  (:MIPS32R6 #.(ash 1 6))       ; Mips32r6 ISA
  (:MIPS2 #.(ash 1 7))          ; Mips II ISA
  (:V9 #.(ash 1 4))             ; SparcV9 mode (Sparc)
  (:QPX #.(ash 1 4))            ; Quad Processing eXtensions mode (PPC)
  (:M68K_000 #.(ash 1 1))       ; M68K 68000 mode
  (:M68K_010 #.(ash 1 2))       ; M68K 68010 mode
  (:M68K_020 #.(ash 1 3))       ; M68K 68020 mode
  (:M68K_030 #.(ash 1 4))       ; M68K 68030 mode
  (:M68K_040 #.(ash 1 5))       ; M68K 68040 mode
  (:M68K_060 #.(ash 1 6))       ; M68K 68060 mode
  (:BIG_ENDIAN #.(ash 1 31))    ; big-endian mode
  (:MIPS32 #.(ash 1 2))         ; Mips32 ISA (Mips)
  (:MIPS64 #.(ash 1 3))         ; Mips64 ISA (Mips)
  (:M680X_6301 #.(ash 1 1))     ; M680X Hitachi 6301,6303 mode
  (:M680X_6309 #.(ash 1 2))     ; M680X Hitachi 6309 mode
  (:M680X_6800 #.(ash 1 3))     ; M680X Motorola 6800,6802 mode
  (:M680X_6801 #.(ash 1 4))     ; M680X Motorola 6801,6803 mode
  (:M680X_6805 #.(ash 1 5))     ; M680X Motorola/Freescale 6805 mode
  (:M680X_6808 #.(ash 1 6))     ; M680X Motorola/Freescale/NXP 68HC08 mode
  (:M680X_6809 #.(ash 1 7))     ; M680X Motorola 6809 mode
  (:M680X_6811 #.(ash 1 8))     ; M680X Motorola/Freescale/NXP 68HC11 mode
  (:M680X_CPU12 #.(ash 1 9))    ; M680X Motorola/Freescale/NXP CPU12
                                ; used on M68HC12/HCS12
  (:M680X_HCS08 #.(ash 1 10)))  ; M680X Freescale/NXP HCS08 mode

(defcfun "cs_version" :uint
  "Return combined API version & major and minor version numbers.

@major: major number of API version
@minor: minor number of API version

@return hexical number as (major << 8 | minor), which encodes both
        major & minor versions.
        NOTE: This returned value can be compared with version number made
        with macro CS_MAKE_VERSION

For example, second API version would return 1 in @major, and 1 in @minor
The return value would be 0x0101

NOTE: if you only care about returned value, but not major and minor values,
set both @major & @minor arguments to NULL."
  (major :int)
  (minor :int))

(defcfun "cs_open" capstone-error
  "Initialize CS handle: this must be done before any usage of CS.

@arch: architecture type (CS_ARCH_*)
@mode: hardware mode. This is combined of CS_MODE_*
@handle: pointer to handle, which will be updated at return time

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (arch capstone-architecture)
  (mode capstone-mode)
  (handle (:pointer capstone-handle)))

(defcfun "cs_close" capstone-error
  "Close CS handle: MUST do to release the handle when it is not used anymore.
NOTE: this must be only called when there is no longer usage of Capstone,
not even access to cs_insn array. The reason is the this API releases some
cached memory, thus access to any Capstone API after cs_close() might crash
your application.

In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

@handle: pointer to a handle returned by cs_open()

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (handle (:pointer capstone-handle)))

(defcfun "cs_disasm" :uint
  "Disassemble binary code, given the code buffer, size, address
and number of instructions to be decoded.
This API dynamically allocate memory to contain disassembled
instruction.  Resulting instructions will be put into @*insn

NOTE 1: this API will automatically determine memory needed to
contain output disassembled instructions in @insn.

NOTE 2: caller must free the allocated memory itself to avoid
memory leaking.

NOTE 3: for system with scarce memory to be dynamically
allocated such as OS kernel or firmware, the API
cs_disasm_iter() might be a better choice than cs_disasm(). The
reason is that with cs_disasm(), based on limited available
memory, we have to calculate in advance how many instructions
to be disassembled, which complicates things. This is
especially troublesome for the case @count=0, when cs_disasm()
runs uncontrollably (until either end of input buffer, or when
it encounters an invalid instruction).

@handle: handle returned by cs_open()
@code: buffer containing raw binary code to be disassembled.
@code_size: size of the above code buffer.
@address: address of the first instruction in given raw code
          buffer.
@insn: array of instructions filled in by this API.
          NOTE: @insn will be allocated by this function, and
                should be freed with cs_free() API.
@count: number of instructions to be disassembled, or 0 to get
        all of them


@return: the number of successfully disassembled instructions,
or 0 if this function failed to disassemble the given code

On failure, call cs_errno() for error code."
  (handle capstone-handle)
  (code (:pointer :uint8))
  (code_size size-t)
  (address :uint64)
  (count size-t)
  (instructions (:pointer (:pointer (:struct capstone-instruction)))))

(defcfun "cs_disasm_iter" :boolean
  "Fast API to disassemble binary code, given the code buffer, size, address
and number of instructions to be decoded.
This API puts the resulting instruction into a given cache in @insn.
See tests/test_iter.c for sample code demonstrating this API.

NOTE 1: this API will update @code, @size & @address to point to the next
instruction in the input buffer. Therefore, it is convenient to use
cs_disasm_iter() inside a loop to quickly iterate all the instructions.
While decoding one instruction at a time can also be achieved with
cs_disasm(count=1), some benchmarks shown that cs_disasm_iter() can be 30%
faster on random input.

NOTE 2: the cache in @insn can be created with cs_malloc() API.

NOTE 3: for system with scarce memory to be dynamically allocated such as
OS kernel or firmware, this API is recommended over cs_disasm(), which
allocates memory based on the number of instructions to be disassembled.
The reason is that with cs_disasm(), based on limited available memory,
we have to calculate in advance how many instructions to be disassembled,
which complicates things. This is especially troublesome for the case
@count=0, when cs_disasm() runs uncontrollably (until either end of input
buffer, or when it encounters an invalid instruction).

@handle: handle returned by cs_open()
@code: buffer containing raw binary code to be disassembled
@size: size of above code
@address: address of the first insn in given raw code buffer
@insn: pointer to instruction to be filled in by this API.

@return: true if this API successfully decode 1 instruction,
or false otherwise.

On failure, call cs_errno() for error code."
  (handle capstone-handle)
  (code (:pointer (:pointer :uint8)))
  (size (:pointer size-t))
  (address (:pointer :uint64))
  (instructions (:pointer (:struct capstone-instruction))))

(defcfun "cs_errno" capstone-error
  "Report the last error number when some API function fail.
Like glibc's errno, cs_errno might not retain its old value once accessed.

@handle: handle returned by cs_open()

@return: error code of cs_err enum type (CS_ERR_*, see above)"
  (handle (:pointer capstone-handle)))

(defcfun "cs_malloc" (:pointer (:struct capstone-instruction))
  "Allocate memory for 1 instruction to be used by cs_disasm_iter().

@handle: handle returned by cs_open()

NOTE: when no longer in use, you can reclaim the memory allocated for
this instruction with cs_free(insn, 1)"
  (handle capstone-handle))

(defcfun "cs_free" :void
  "Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

@insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
@count: number of cs_insn structures returned by cs_disasm(), or 1
        to free memory allocated by cs_malloc()."
  (instructions (:pointer (:struct capstone-instruction)))
  (count size-t))


;;;; CLOS wrapper.
(defclass capstone-engine ()
  ((architecture :reader architecture :type keyword)
   (mode :reader mode :type keyword)
   (cs-handle)))

(defmethod initialize-instance :after ((capstone-engine capstone-engine) &key)
  (assert (foreign-enum-value 'capstone-arch (architecture capstone-engine)))
  (assert (foreign-enum-value 'capstone-mode (mode capstone-engine)))
  (with-slots (architecture mode cs-handle) capstone-engine
    (setf cs-handle (foreign-alloc 'capstone-handle))
    (assert (eql :ok (cs-open architecture mode cs-handle))
            (architecture mode)
            "Capstone Engine initialization with `cs-open' failed with ~a."
            (cs-errno cs-handle)))
  (sb-impl::finalize capstone-engine
                     (lambda ()
                       (with-slots (cs-handle) capstone-engine
                         (cs-close cs-handle)))))


;;;; Test.
(defun test-disasm ()
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
            (format t "~x: ~a ~a~%" address mnemonic op_str)))))))
