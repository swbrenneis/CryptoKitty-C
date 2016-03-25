CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include
CPPFLAGS= -Wall -g -MMD -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= RSAKeyPairGenerator.cc RSAPublicKey.cc RSAPrivateCrtKey.cc \
			 RSAPrivateModKey.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
