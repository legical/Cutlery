FILE1 = qsort_small.c
FILE2 = qsort_large.c
BINFILE = qsort_small qsort_large
all: qsort_small qsort_large

qsort_small: qsort_small.c Makefile
	gcc qsort_small.c -o qsort_small -lm
qsort_large: qsort_large.c Makefile
	gcc qsort_large.c -o qsort_large -lm

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		echo "mv $(BINFILE) to $(OUT)"; \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
	fi
	rm -rf qsort_small qsort_large output*
