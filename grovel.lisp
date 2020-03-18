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
