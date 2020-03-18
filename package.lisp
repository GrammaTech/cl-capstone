(defpackage :capstone
  (:use :gt :cffi)
  (:import-from :static-vectors
                :with-static-vector
                :static-vector-pointer)
  (:export :disasm
           ;; Fields of the instruction object.
           :address :mnemonic :opstr))
