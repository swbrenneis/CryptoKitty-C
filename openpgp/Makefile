DEV_HOME= $(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include -I../include/openpgp -I$(DEV_HOME)/include
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES=  encode/Radix64.cc packet/Packet.cc packet/PKESessionKey.cc \
			  packet/PublicKey.cc packet/Signature.cc packet/UserAttribute.cc \
			packet/UserID.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
