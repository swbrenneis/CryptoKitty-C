DEV_HOME=$(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include
CPPFLAGS= -Wall -g -MMD -std=c++11 -O0 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

LD= g++
LD_FLAGS= -g -Wall -fpermissive
LD_LIBRARY_PATH= -L$(DEV_HOME)/lib
LD_LIBRARIES= -lcryptokitty

CPP_SOURCES= CipherTest.cc DigestTest.cc MACTest.cc RandomTest.cc SignatureTest.cc \
			 Test.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)
LIBRARY= $(DEV_HOME)/lib/libcryptokitty.so

PROGRAM= cktest

.PHONY: clean

all: $(PROGRAM)

$(PROGRAM): $(CPP_OBJECT) $(LIBRARY)
	$(LD) $(LD_FLAGS) $(LD_LIBRARY_PATH) $(LD_LIBRARIES) -o $(PROGRAM) $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
