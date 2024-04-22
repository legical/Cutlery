BINFILE = dijkstra_large dijkstra_small

all:  dijkstra_large dijkstra_small

dijkstra_large: dijkstra_large.c Makefile
	gcc dijkstra_large.c -o dijkstra_large

dijkstra_small: dijkstra_small.c Makefile
	gcc dijkstra_small.c -o dijkstra_small 

clean:
	@if [ -z "$(OUT)" ]; then \
		echo "clean $(pwd)"; \
	else \
		mkdir -p $(OUT); \
		mv -f $(BINFILE) $(OUT); \
		echo "mv $(BINFILE) to $(OUT)"; \
	fi
	rm -rf dijkstra_large dijkstra_small output*
