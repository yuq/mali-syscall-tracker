#!makefile

MALI_API_VERSION ?= r4p0

ifeq ($(MALI_API_VERSION),r4p0)
	CONFIG = -DCONFIG_MALI_API_R4P0
else ifeq ($(MALI_API_VERSION),r6p1)
	CONFIG = -DCONFIG_MALI_API_R6P1
endif

libMali_wrap.so: main.c
	gcc -shared -fPIC -g $(CONFIG) -o $@ $^ -ldl -lpthread
