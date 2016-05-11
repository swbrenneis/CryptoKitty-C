DEV_HOME= $(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include -I$(DEV_HOME)/include
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= Alert.cc ChangeCipherSpec.cc CipherSuiteManager.cc CipherText.cc \
			 ClientHello.cc ClientKeyExchange.cc ConnectionState.cc \
			 ExtensionManager.cc Finished.cc HandshakeBody.cc HandshakeRecord.cc \
			 PGPCertificate.cc Plaintext.cc RecordProtocol.cc ServerCertificate.cc \
			 ServerHello.cc ServerKeyExchange.cc 
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
