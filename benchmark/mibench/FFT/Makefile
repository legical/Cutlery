OBJ = main.o fftmisc.o  fourierf.o
FILE = main.c fftmisc.c  fourierf.c
CFLAGS = -g
BINFILE = fft

fft: ${OBJ} Makefile
	gcc  ${CFLAGS} ${OBJ} -o fft -lm
fftmisc.o: fftmisc.c
	gcc ${CFLAGS} -c fftmisc.c
fourierf.o: fourierf.c
	gcc ${CFLAGS} -c fourierf.c
main.o: main.c
	gcc ${CFLAGS} -c main.c

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
		echo "mv $(BINFILE) to $(OUT)"; \
	fi
	rm -rf *.o fft output*
