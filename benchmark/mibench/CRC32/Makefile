BINFILE = crc

crc: crc_32.c Makefile
	gcc crc_32.c -o crc 

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
		echo "mv $(BINFILE) to $(OUT)"; \
	fi
	rm -rf crc output*
