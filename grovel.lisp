;;;; grovel.lisp --- CFFI groveler directives for capstone.h
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
(include "stdlib.h" "capstone/capstone.h")

(in-package :capstone)

(ctype size-t "size_t")

(cstruct cs_x86 "cs_x86")
(cstruct cs_arm64 "cs_arm64")
(cstruct cs_arm "cs_arm")
(cstruct cs_m68k "cs_m68k")
(cstruct cs_mips "cs_mips")
(cstruct cs_ppc "cs_ppc")
(cstruct cs_sparc "cs_sparc")
(cstruct cs_sysz "cs_sysz")
(cstruct cs_xcore "cs_xcore")
(cstruct cs_tms320c64x "cs_tms320c64x")
(cstruct cs_m680x "cs_m680x")
(cstruct cs_evm "cs_evm")
