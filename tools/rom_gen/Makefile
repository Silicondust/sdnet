
SRCS += ../common/DoubleEndedMemory.cpp
SRCS += rom_gen.cpp

CPPFLAGS += -Wall -O2 -g
CPPFLAGS += -I../common
EXTLIBS += -lstdc++

ifeq ($(OS),Windows_NT)
BINEXT := .exe
endif

rom_gen$(BINEXT) : $(SRCS)
	gcc $(CPPFLAGS) $(SRCS) $(EXTLIBS) -o $@

clean:
	rm -f rom_gen$(BINEXT)
