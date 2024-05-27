MAKEFLAGS += -s

GCC 	= x86_64-w64-mingw32-gcc

INC		= -I Include
CORE	= $(wildcard Source/Core/*.c)
COM     = $(wildcard Source/Common/*.c)
CFLAGS 	= -s -w -DDEBUG -D NtCreateThreadEx
OUT		= -o Bin/ForkRun.exe -lkernel32 -luser32

RL:
	$(GCC) $(INC) $(CFLAGS) $(COM) $(CORE) Source/Main.c $(OUT)