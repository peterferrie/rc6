msvc:
		cl /nologo /O2 /Ot /DTEST test.c rc6.c
gnu:
		gcc -DTEST -Wall -O2 test.c rc6.c -otest	 
clang:
		clang -DTEST -Wall -O2 test.c rc6.c -otest	    