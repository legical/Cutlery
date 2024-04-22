susan: susan.c Makefile
	gcc -O4 -o susan susan.c -lm 

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "rm susan all"; \
	else \
		echo "mv susan to $(OUT)"; \
		mkdir -p $(OUT); \
		mv -f susan $(OUT); \
	fi
	rm -rf susan output*
