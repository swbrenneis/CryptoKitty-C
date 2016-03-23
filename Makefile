LD= g++
LDPATHS= -LNTL/lib
LDLIBS=  -lrt -lntl -lgmp
LDFLAGS= -Wall -g -shared $(LDPATHS) $(LDLIBS)

LIBRARY= libcryptokitty.so

DATA_OBJECT= data/BigInteger.o data/ByteArray.o data/NanoTime.o data/Scalar32.o \
			 data/Scalar64.o
DATA_SOURCE= $(DATA_OBJECT:.o=.cc)
DIGEST_OBJECT= digest/CKSHA256.o digest/DigestBase.o
DIGEST_SOURCE= $(DIGEST_OBJECT:.o=.cc)
KEYS_OBJECT= keys/RSAKeyPairGenerator.o
KEYS_SOURCE= $(KEYS_OBJECT:.o=.cc)
RANDOM_OBJECT= random/BBSSecureRandom.o random/CMWCRandom.o random/Random.o \
			   random/SecureRandom.o
RANDOM_SOURCE= $(RANDOM_OBJECT:.o=.cc)

LDOBJECT= $(DATA_OBJECT) $(DIGEST_OBJECT) $(KEYS_OBJECT) $(RANDOM_OBJECT)
LDDEPEND= $(LDOBJECT:.o=.d)

.SUFFIXES:

.PHONY: clean

all: $(LIBRARY)

$(DATA_OBJECT): $(DATA_SOURCE)
	$(MAKE) -C data

$(DIGEST_OBJECT): $(DIGEST_SOURCE)
	$(MAKE) -C digest

$(KEYS_OBJECT): $(KEYS_SOURCE)
	$(MAKE) -C keys

$(RANDOM_OBJECT): $(RANDOM_SOURCE)
	$(MAKE) -C random

$(LIBRARY): $(LDOBJECT)
	    $(LD) -o $@ $(LDOBJECT) $(LDFLAGS)

clean:
	rm -f $(LIBRARY)
	cd data && $(MAKE) clean
	cd digest && $(MAKE) clean
	cd keys && $(MAKE) clean
	cd random && $(MAKE) clean
	cd test && $(MAKE) clean

-include $(LDDEPEND)
