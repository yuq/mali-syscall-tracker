#!/bin/bash

LD_PRELOAD=./libMali_wrap.so DISPLAY=:0 $@
