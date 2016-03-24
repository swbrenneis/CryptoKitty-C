LD= g++
LDPATHS= -LNTL/lib
LDLIBS=  -lrt -lntl -lgmp
LDFLAGS= -Wall -g -shared $(LDPATHS) $(LDLIBS)

LIBRARY= libcryptokitty.so

CIPHER_OBJECT= cipher/RSA.o
CIPHER_HEADER= include/cipher/RSA.h
CIPHER_SOURCE= $(CIPHER_OBJECT:.o=.cc)
DATA_OBJECT= data/BigInteger.o data/ByteArray.o data/NanoTime.o data/Scalar32.o \
			 data/Scalar64.o
DATA_HEADER= include/data/BigInteger.h include/data/ByteArray.h \
			 include/data/NanoTime.h include/data/Scalar32.h  \
			include/data/Scalar64.h
DATA_SOURCE= $(DATA_OBJECT:.o=.cc)
DIGEST_OBJECT= digest/SHA256.o digest/DigestBase.o
DIGEST_HEADER= include/digest/SHA256.h include/digest/DigestBase.h
DIGEST_SOURCE= $(DIGEST_OBJECT:.o=.cc)
KEYS_OBJECT= keys/RSAKeyPairGenerator.o keys/RSAPublicKey.o keys/RSAPrivateCrtKey.o
KEYS_HEADER= include/keys/RSAKeyPairGenerator.h include/keys/RSAPublicKey.h \
			include/keys/RSAPrivateCrtKey.h
KEYS_SOURCE= $(KEYS_OBJECT:.o=.cc)
RANDOM_OBJECT= random/BBSSecureRandom.o random/CMWCRandom.o random/Random.o \
			   random/SecureRandom.o
RANDOM_HEADER= include/random/BBSSecureRandom.h include/random/CMWCRandom.h \
			   include/random/Random.h include/random/SecureRandom.h
RANDOM_SOURCE= $(RANDOM_OBJECT:.o=.cc)
SIGNATURE_OBJECT= signature/RSASignature.o
SIGNATURE_HEADER= include/signature/RSASignature.h
SIGNATURE_SOURCE= $(SIGNATURE_OBJECT:.o=.cc)

LDOBJECT= $(CIPHER_OBJECT) $(DATA_OBJECT) $(DIGEST_OBJECT) $(KEYS_OBJECT) \
		  $(RANDOM_OBJECT) $(SIGNATURE_OBJECT)

.SUFFIXES:

.PHONY: clean

all: $(LIBRARY)

$(CIPHER_OBJECT): $(CIPHER_SOURCE) $(CIPHER_HEADER)
	$(MAKE) -C cipher

$(DATA_OBJECT): $(DATA_SOURCE) $(DATA_HEADER)
	$(MAKE) -C data

$(DIGEST_OBJECT): $(DIGEST_SOURCE) $(DIGEST_HEADER)
	$(MAKE) -C digest

$(KEYS_OBJECT): $(KEYS_SOURCE) $(KEYS_HEADER)
	$(MAKE) -C keys

$(RANDOM_OBJECT): $(RANDOM_SOURCE) $(RANDOM_HEADER)
	$(MAKE) -C random

$(SIGNATURE_OBJECT): $(SIGNATURE_SOURCE) $(SIGNATURE_HEADER)
	$(MAKE) -C signature

$(LIBRARY): $(LDOBJECT)
	    $(LD) -o $@ $(LDOBJECT) $(LDFLAGS)

clean:
	rm -f $(LIBRARY)
	cd cipher && $(MAKE) clean
	cd data && $(MAKE) clean
	cd digest && $(MAKE) clean
	cd keys && $(MAKE) clean
	cd random && $(MAKE) clean
	cd signature && $(MAKE) clean

