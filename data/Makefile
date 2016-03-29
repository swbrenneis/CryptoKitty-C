DEV_HOME=$(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include -I$(DEV_HOME)/include
CPPFLAGS= -Wall -g -MMD -fPIC -std=c++11 $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= BigInteger.cc ByteArray.cc NanoTime.cc Scalar32.cc Scalar64.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
