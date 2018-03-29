
SRCS += ../common/DoubleEndedMemory.cpp
SRCS += webserver_page_gen.cpp

CPPFLAGS += -Wall -O2 -g
CPPFLAGS += -I../common
EXTLIBS += -lstdc++

ifeq ($(OS),Windows_NT)
BINEXT := .exe
endif

webserver_page_gen$(BINEXT) : $(SRCS)
	gcc $(CPPFLAGS) $(SRCS) $(EXTLIBS) -o $@

clean:
	rm -f webserver_page_gen$(BINEXT)
