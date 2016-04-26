DEV_HOME= $(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include -I$(DEV_HOME)/include
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= Alert.cc CipherSuiteManager.cc ClientHello.cc ConnectionState.cc \
			 ExtensionManager.cc HandshakeRecord.cc PGPCertificate.cc \
			 Plaintext.cc SecurityParameters.cc ServerCertificate.cc ServerHello.cc \
			 ServerKeyExchange.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
