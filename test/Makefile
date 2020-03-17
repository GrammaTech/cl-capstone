# From http://www.capstone-engine.org/lang_c.html
LIBNAME = capstone

test1: test1.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
