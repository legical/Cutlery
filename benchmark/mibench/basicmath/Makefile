FILE1 = basicmath_small.c   rad2deg.c  cubic.c   isqrt.c
FILE2 = basicmath_large.c   rad2deg.c  cubic.c   isqrt.c
BINFILE = basicmath_small basicmath_large

all: basicmath_small basicmath_large

basicmath_small: ${FILE1} Makefile
	gcc ${FILE1} -o basicmath_small -lm
basicmath_large: ${FILE2} Makefile
	gcc ${FILE2} -o basicmath_large -lm

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
		echo "mv $(BINFILE) to $(OUT)"; \
	fi
	rm -rf basicmath_small basicmath_large output*
