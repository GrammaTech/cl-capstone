;;;; capstone.lisp --- CFFI bindings to libcapstone.so
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
(in-package :capstone/raw)
#+debug (declaim (optimize (debug 3)))

(cffi:define-foreign-library libcapstone
  (t (:default "libcapstone")))
(use-foreign-library libcapstone)


;;;; CFFI definitions.
(defctype cs-handle :pointer
  "Capstone engine handle.")

(defcstruct cs-insn
  "Detail information of disassembled instruction."
  (id :unsigned-int)
  (address :uint64)
  (insn-size :uint16)
  (bytes :uint8 :count 16)
  (mnemonic :char :count 32)            ; CS_MNEMONIC_SIZE
  (op-str :char :count 160)
  (cs-detail (:pointer (:struct cs-detail))))

(defcenum cs-error
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

(defcenum cs-architecture
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

(defcenum cs-mode
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

(defcenum cs-option-type
  (:INVALID 0)         ; No option specified
  :SYNTAX              ; Assembly output syntax
  :DETAIL              ; Break down instruction structure into details
  :MODE                ; Change engine's mode at run-time
  :MEM                 ; User-defined dynamic memory related functions
  :SKIPDATA ; Skip data when disassembling. Then engine is in SKIPDATA mode.
  :SKIPDATA_SETUP    ; Setup user-defined function for SKIPDATA option
  :MNEMONIC          ; Customize instruction mnemonic
  :UNSIGNED)         ; print immediate operands in unsigned form

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

(defcfun "cs_support" :boolean
  "This API can be used to either ask for archs supported by this library,
or check to see if the library was compile with 'diet' option (or called
in 'diet' mode).

To check if a particular arch is supported by this library, set @query to
arch mode (CS_ARCH_* value).
To verify if this library supports all the archs, use CS_ARCH_ALL.

To check if this library is in 'diet' mode, set @query to CS_SUPPORT_DIET.

@return True if this library supports the given arch, or in 'diet' mode."
  (query :int))

(defcfun "cs_open" cs-error
  "Initialize CS handle: this must be done before any usage of CS.

@arch: architecture type (CS_ARCH_*)
@mode: hardware mode. This is combined of CS_MODE_*
@handle: pointer to handle, which will be updated at return time

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (arch cs-architecture)
  (mode cs-mode)
  (handle (:pointer cs-handle)))

(defcfun "cs_close" cs-error
  "Close CS handle: MUST do to release the handle when it is not used anymore.
NOTE: this must be only called when there is no longer usage of Capstone,
not even access to cs_insn array. The reason is the this API releases some
cached memory, thus access to any Capstone API after cs_close() might crash
your application.

In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

@handle: pointer to a handle returned by cs_open()

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (handle (:pointer cs-handle)))

(defcfun "cs_option" cs-error
  "Set option for disassembling engine at runtime

@handle: handle returned by cs_open()
@type: type of option to be set
@value: option value corresponding with @type

@return: CS_ERR_OK on success, or other value on failure.
Refer to cs_err enum for detailed error.

NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
even before cs_open()"
  (handle cs-handle)
  (type cs-option-type)
  (value size-t))

(defcfun "cs_errno" cs-error
  "Report the last error number when some API function fail.
Like glibc's errno, cs_errno might not retain its old value once accessed.

@handle: handle returned by cs_open()

@return: error code of cs_err enum type (CS_ERR_*, see above)"
  (handle (:pointer cs-handle)))

(defcfun "cs_strerror" :string
  "Return a string describing given error code.

@code: error code (see CS_ERR_* above)

@return: returns a pointer to a string that describes the error code
         passed in the argument @code"
  (code cs-error))

(defcfun "cs_disasm" size-t
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
  (handle cs-handle)
  (code (:pointer :uint8))
  (code_size size-t)
  (address :uint64)
  (count size-t)
  (instructions (:pointer (:pointer (:struct cs-insn)))))

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
  (handle cs-handle)
  (code (:pointer (:pointer :uint8)))
  (size (:pointer size-t))
  (address (:pointer :uint64))
  (instructions (:pointer (:struct cs-insn))))

(defcfun "cs_malloc" (:pointer (:struct cs-insn))
  "Allocate memory for 1 instruction to be used by cs_disasm_iter().

@handle: handle returned by cs_open()

NOTE: when no longer in use, you can reclaim the memory allocated for
this instruction with cs_free(insn, 1)"
  (handle cs-handle))

(defcfun "cs_free" :void
  "Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

@insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
@count: number of cs_insn structures returned by cs_disasm(), or 1
        to free memory allocated by cs_malloc()."
  (instructions (:pointer (:struct cs-insn)))
  (count size-t))

(defcfun "cs_reg_name" :string
  "Return friendly name of register in a string.
Find the instruction id from header file of corresponding architecture (arm.h for ARM,
x86.h for X86, ...)

WARN: when in 'diet' mode, this API is irrelevant because engine does not
store register name.

@handle: handle returned by cs_open()
@reg_id: register id

@return: string name of the register, or NULL if @reg_id is invalid."
  (handle cs-handle)
  (register-id :unsigned-int))

(defcfun "cs_insn_name" :string
  "Return friendly name of an instruction in a string.
Find the instruction id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

WARN: when in 'diet' mode, this API is irrelevant because the engine does not
store instruction name.

@handle: handle returned by cs_open()
@insn_id: instruction id

@return: string name of the instruction, or NULL if @insn_id is invalid."
  (handle cs-handle)
  (instruction-id :unsigned-int))

(defcfun "cs_group_name" :string
  "Return friendly name of a group id (that an instruction can belong to)
Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

WARN: when in 'diet' mode, this API is irrelevant because the engine does not
store group name.

@handle: handle returned by cs_open()
@group_id: group id

@return: string name of the group, or NULL if @group_id is invalid."
  (handle cs-handle)
  (group-id :unsigned-int))

(defcfun "cs_insn_group" :boolean
  "Check if a disassembled instruction belong to a particular group.
Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
Internally, this simply verifies if @group_id matches any member of insn->groups array.

NOTE: this API is only valid when detail option is ON (which is OFF by default).

WARN: when in 'diet' mode, this API is irrelevant because the engine does not
update @groups array.

@handle: handle returned by cs_open()
@insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
@group_id: group that you want to check if this instruction belong to.

@return: true if this instruction indeed belongs to the given group, or false otherwise."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (group-id :unsigned-int))

(defcfun "cs_reg_read" :boolean
  "Check if a disassembled instruction IMPLICITLY used a particular register.
Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
Internally, this simply verifies if @reg_id matches any member of insn->regs_read array.

NOTE: this API is only valid when detail option is ON (which is OFF by default)

WARN: when in 'diet' mode, this API is irrelevant because the engine does not
update @regs_read array.

@insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
@reg_id: register that you want to check if this instruction used it.

@return: true if this instruction indeed implicitly used the given register, or false otherwise."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (register-id :unsigned-int))

(defcfun "cs_reg_write" :boolean
  "Check if a disassembled instruction IMPLICITLY modified a particular register.
Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
Internally, this simply verifies if @reg_id matches any member of insn->regs_write array.

NOTE: this API is only valid when detail option is ON (which is OFF by default)

WARN: when in 'diet' mode, this API is irrelevant because the engine does not
update @regs_write array.

@insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
@reg_id: register that you want to check if this instruction modified it.

@return: true if this instruction indeed implicitly modified the given register, or false otherwise."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (register-id :unsigned-int))

(defcfun "cs_op_count" :int
  "Count the number of operands of a given type.
Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

NOTE: this API is only valid when detail option is ON (which is OFF by default)

@handle: handle returned by cs_open()
@insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
@op_type: Operand type to be found.

@return: number of operands of given type @op_type in instruction @insn,
or -1 on failure."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (operand-type :unsigned-int))

(defcfun "cs_op_index" :int
  "Retrieve the position of operand of given type in <arch>.operands[] array.
Later, the operand can be accessed using the returned position.
Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

NOTE: this API is only valid when detail option is ON (which is OFF by default)

@handle: handle returned by cs_open()
@insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
@op_type: Operand type to be found.
@position: position of the operand to be found. This must be in the range
       		[1, cs_op_count(handle, insn, op_type)]

@return: index of operand of given type @op_type in <arch>.operands[] array
in instruction @insn, or -1 on failure."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (operand-type :unsigned-int)
  (position :unsigned-int))

#+broken
(progn
(defcstruct cs-registers
  (registers :uint16 :count 64))

(defcfun "cs_regs_access" cs-error
  "Retrieve all the registers accessed by an instruction, either explicitly or
implicitly.

WARN: when in 'diet' mode, this API is irrelevant because engine does not
store registers.

@handle: handle returned by cs_open()
@insn: disassembled instruction structure returned from cs_disasm() or cs_disasm_iter()
@regs_read: on return, this array contains all registers read by instruction.
@regs_read_count: number of registers kept inside @regs_read array.
@regs_write: on return, this array contains all registers written by instruction.
@regs_write_count: number of registers kept inside @regs_write array.

@return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
for detailed error)."
  (handle cs-handle)
  (instruction (:pointer (:struct cs-insn)))
  (registers-read (:struct cs-registers))
  (registers-read-count (:pointer :uint8))
  (registers-write (:struct cs-registers))
  (registers-write-count (:pointer :uint8)))
)
