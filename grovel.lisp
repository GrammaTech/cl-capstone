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

(in-package :capstone/raw)

(ctype size-t "size_t")
(cstruct cs-detail "cs_detail")
