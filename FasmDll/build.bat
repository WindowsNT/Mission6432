cd /D "%~dp0"
..\fasm\FASM.EXE fasmdll.asm fasmdll.dll
lib /def:fasmdll.def /out:fasmdll.lib /machine:x86
VERIFY > nul
