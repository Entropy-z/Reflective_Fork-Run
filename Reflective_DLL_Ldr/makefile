MAKEFLAGS += -s

GCC 	= x86_64-w64-mingw32-gcc
NASM    = nasm

INC		= -I Include
CORE	= $(wildcard Source/Core/*.c)
COM     = $(wildcard Source/Common/*.c)

CFLAGS  = -w -Wall -s -Os -Wextra -masm=intel -shared -fPIC -e DllMain
CFLAGS += -fno-asynchronous-unwind-tables -nostdlib -fno-diagnostics-show-caret
CFLAGS += -fdata-sections -ffunction-sections -Wl,--gc-sections

OUT		= -o Bin/OblivLdr.x64.dll -luser32

rdll:
	nasm -f win64 Source/Asm/BaseAddrRet.s -o Source/BaseAddrRet.o
	$(GCC) $(INC) $(CFLAGS) $(COM) $(CORE) Source/*.o Source/DllMain.c $(OUT)
	rm Source/*.o

hasher:
	x86_64-w64-mingw32-gcc.exe -w -s .\Scripts\Hasher.c -o .\Scripts\Hasher.exe
