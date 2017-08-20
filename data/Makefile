UNAME= $(shell uname)

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include $(TAILS_INCLUDE)
CPPFLAGS= -Wall -g -MMD -std=c++11 $(CPPDEFINES) $(CPPINCLUDES)
ifneq ($(UNAME), CYGWIN_NT-10.0)
CPPFLAGS+= -fPIC
endif

CPP_SOURCES= BigInteger.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
