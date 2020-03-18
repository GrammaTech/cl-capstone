(include "stdlib.h" "capstone/capstone.h")

(in-package :capstone)

(ctype size-t "size_t")

#+broken
(cstruct capstone-detail "cs_detail"
         (regs-read "regs_read")
         (regs-read-count "regs_read_count")
         (regs-write "regs_write")
         (regs-write-count "regs_write_count")
         (groups "groups")
         (groups-count "groups_count")
         (cs-x86 "cs_x86")
         (cs-arm64 "cs_arm64")
         (cs-arm "cs_arm")
         (cs-m68k "cs_m68k")
         (cs-mips "cs_mips")
         (cs-ppc "cs_ppc")
         (cs-sparc "cs_sparc")
         (cs-sysz "cs_sysz")
         (cs-xcore "cs_xcore")
         (cs-tms320c64x "cs_tms320c64x")
         (cs-m680x "cs_m680x")
         (cs-evm "cs_evm"))
