UNAME= $(shell uname)
ifeq ($(UNAME), Darwin)
DEV_HOME=$(HOME)/Development
endif
ifeq ($(UNAME), Linux)
DEV_HOME=$(HOME)/dev
endif

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= Base64.cc DERCodec.cc GCMCodec.cc PEMCodec.cc RSACodec.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
