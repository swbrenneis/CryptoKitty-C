LD= g++
LDPATHS=
LDLIBS=  -lrt
LDFLAGS= -Wall -g -shared $(LDPATHS) $(LDLIBS)

LIBRARY= libcryptokitty.so

DATA_OBJECT= data/BigInteger.o data/ByteArray.o data/NanoTime.o data/Scalar32.o
DATA_SOURCE= $(DTA_OBJECT:.o=.cc)
DIGEST_OBJECT= digest/CKSHA256.o digest/DigestBase.o
RANDOM_OBJECT= random/CMWCRandom.o random/Random.o

LDOBJECT= $(DATA_OBJECT) $(DIGEST_OBJECT) $(RANDOM_OBJECT)
LDDEPEND= $(LDOBJECT:.o=.d)

.SUFFIXES:

.PHONY: clean

all: $(LIBRARY)

$(DATA_OBJECT): $(DATA_SOURCE)
	$(MAKE) -C data

$(DIGEST_OBJECT):
	$(MAKE) -C digest

$(RANDOM_OBJECT):
	$(MAKE) -C random

$(LIBRARY): $(LDOBJECT)
	    $(LD) $(LDFLAGS) -o $@ $(LDOBJECT)

clean:
	rm -f $(LIBRARY)
	cd data && $(MAKE) clean
	cd digest && $(MAKE) clean
	cd random && $(MAKE) clean

-include $(LDDEPEND)
