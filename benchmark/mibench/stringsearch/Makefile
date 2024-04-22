FILE1 = bmhasrch.c  bmhisrch.c  bmhsrch.c  pbmsrch_small.c 
FILE2 = bmhasrch.c  bmhisrch.c  bmhsrch.c  pbmsrch_large.c 

all: search_small search_large

search_small: ${FILE1} Makefile
	gcc ${FILE1} -o search_small

search_large: ${FILE2} Makefile
	gcc ${FILE2} -o search_large

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		echo "mv search_small search_large to $(OUT)"; \
		mkdir -p $(OUT); \
		mv -f search_small search_large $(OUT); \
	fi
	rm -rf search_small search_large output*
