## usage
1. Boot an OS with close source driver installed into command line
2. Start X server with xinit
3. Build this tool by just make
3. Run some OGL app you want to dump the memory with
```
LIMA_WRAP_LOG=<log file path and name> LD_PRELOAD=<path to libMali_wrap.so> DISPLAY=:0 <OGL app>
```
