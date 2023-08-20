CC ?= cc


lchttp.so: lchttp.c
	$(CC) -shared lchttp.c -o lchttp.so
