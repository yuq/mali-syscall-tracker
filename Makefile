#!makefile

libMali_wrap.so: main.c
	gcc -shared -fPIC -g -o $@ $^ -ldl -lpthread
