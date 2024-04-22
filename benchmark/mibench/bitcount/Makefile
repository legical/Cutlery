FILE = bitcnt_1.c bitcnt_2.c bitcnt_3.c bitcnt_4.c bitcnts.c bitfiles.c bitstrng.c bstr_i.c 
BINFILE = bitcnts

bitcnts: ${FILE} Makefile
	gcc ${FILE} -o bitcnts

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
		echo "mv $(BINFILE) to $(OUT)"; \
	fi
	rm -rf bitcnts output*
