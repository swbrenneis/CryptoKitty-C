DEV_HOME=$(HOME)/dev
CK_INCLUDE= $(DEV_HOM)/linclude/CryptoKitty
UNAME= $(shell uname)

LD= g++
CK_LDPATHS= -L$(DEV_HOME)/lib
PGP_LDPATHS= -L.
TLS_LDPATHS= -L.
CK_LDLIBS=  -lntl -lgmp -lcoder -lcthread
PGP_LDLIBS=  -lcoder -lcryptokitty
TLS_LDLIBS=  -lcoder -lcryptokitty -lckpgp
ifeq ($(UNAME), Darwin)
LDFLAGS= -Wall -g -dynamiclib
endif
ifeq ($(UNAME), Linux)
LDFLAGS= -Wall -g -shared
endif

CIPHER_OBJECT= cipher/AES.o cipher/OAEPrsaes.o cipher/PKCS1rsaes.o cipher/PKCS1rsassa.o \
			   cipher/PSSmgf1.o cipher/PSSrsassa.o cipher/RSA.o
CIPHER_HEADER= include/cipher/AES.h include/cipher/OAEPrsaes.h include/cipher/PKCS1rsaes.h \
			   include/cipher/PKCS1rsassa.h include/cipher/PSSmgf1.h \
			   include/cipher/PSSrsassa.h include/cipher/RSA.h
CIPHER_SOURCE= $(CIPHER_OBJECT:.o=.cc)
CIPHERMODES_OBJECT= ciphermodes/CBC.o ciphermodes/CTR.o ciphermodes/GCM.o \
					ciphermodes/MtE.o
CIPHERMODES_HEADER= include/ciphermodes/CBC.h include/ciphermodes/CTR.h \
					include/ciphermodes/GCM.h include/ciphermodes/MtE.h
CIPHERMODES_SOURCE= $(CIPHERMODES_OBJECT:.o=.cc)
DATA_OBJECT= data/BigInteger.o data/NanoTime.o
DATA_HEADER= include/data/BigInteger.h include/data/NanoTime.h
DATA_SOURCE= $(DATA_OBJECT:.o=.cc)
DIGEST_OBJECT= digest/SHA1.o digest/SHA256.o digest/SHA384.o digest/SHA512.o digest/DigestBase.o
DIGEST_HEADER= include/digest/SHA1.h include/digest/SHA256.h include/digest/SHA384.h \
			   include/digest/SHA512.h include/digest/DigestBase.h
DIGEST_SOURCE= $(DIGEST_OBJECT:.o=.cc)
KEYS_OBJECT= keys/DHKeyExchange.o keys/ECDHKeyExchange.o keys/PrivateKey.o \
			 keys/PublicKey.o keys/RSAKeyPairGenerator.o keys/RSAPrivateKey.o \
			 keys/RSAPrivateCrtKey.o keys/RSAPrivateModKey.o \
			 keys/RSAPublicKey.o
KEYS_HEADER= include/keys/DHKeyExchange.h include/keys/ECDHKeyExchange.h \
			 include/keys/PrivateKey.h include/keys/PublicKey.h \
			 include/keys/RSAKeyPairGenerator.h include/keys/RSAPrivateKey.h \
			 include/keys/RSAPrivateCrtKey.h include/keys/RSAPrivateModKey.h \
			 include/keys/RSAPublicKey.h
KEYS_SOURCE= $(KEYS_OBJECT:.o=.cc)
MAC_OBJECT= mac/HMAC.o
MAC_HEADER= include/mac/HMAC.h
MAC_SOURCE= $(MAC_OBJECT:.o=.cc)
OPENPGP_OBJECT= openpgp/encode/ArmoredData.o openpgp/encode/Radix64.o \
				openpgp/key/String2Key.o openpgp/mode/PGPCFM.o \
				openpgp/packet/Encrypted.o openpgp/packet/Packet.o \
				openpgp/packet/PKESessionKey.o openpgp/packet/PublicKey.o \
				openpgp/packet/PublicSubkey.o openpgp/packet/SecretKey.o \
				openpgp/packet/Signature.o openpgp/packet/UserAttribute.o \
				openpgp/packet/UserID.o
OPENPGP_HEADER= include/openpgp/encode/ArmoredData.h include/openpgp/encode/Radix64.h \
				include/openpgp/key/String2Key.h include/openpgp/mode/PGPCFM.h \
				include/openpgp/packet/Encrypted.h include/openpgp/packet/Packet.h \
				include/openpgp/packet/PKESessionKey.h include/openpgp/packet/PublicKey.h \
				include/openpgp/packet/PublicSubkey.h include/openpgp/packet/SecretKey.h \
				include/openpgp/packet/Signature.h include/openpgp/packet/UserAttribute.h \
				include/openpgp/packet/UserID.h
OPENPGP_SOURCE= $(OPENPGP_OBJECT:.o=.cc)
RANDOM_OBJECT= random/BBSSecureRandom.o random/CMWCRandom.o random/FortunaSecureRandom.o \
			   random/FortunaGenerator.o random/Random.o
RANDOM_HEADER= include/random/BBSSecureRandom.h include/random/CMWCRandom.h \
			   include/random/FortunaSecureRandom.h include/random/FortunaGenerator.h \
			   include/random/Random.h include/random/SecureRandom.h
RANDOM_SOURCE= $(RANDOM_OBJECT:.o=.cc)
SIGNATURE_OBJECT= signature/RSASignature.o
SIGNATURE_HEADER= include/signature/RSASignature.h
SIGNATURE_SOURCE= $(SIGNATURE_OBJECT:.o=.cc)
TLS_OBJECT= tls/Alert.o tls/ChangeCipherSpec.o tls/CipherSuiteManager.o tls/CipherText.o \
			tls/ClientHello.o tls/ClientKeyExchange.o tls/ConnectionState.o \
			tls/ExtensionManager.o tls/Finished.o tls/HandshakeBody.o tls/HandshakeRecord.o \
			tls/PGPCertificate.o tls/RecordProtocol.o tls/Plaintext.o \
			tls/ServerCertificate.o tls/ServerHello.o tls/ServerKeyExchange.o
TLS_HEADER= include/tls/Alert.h include/tls/ChangeCipherSpec.h include/tls/CipherSuiteManager.h \
			include/tls/CipherText.h include/tls/ClientHello.h include/tls/ClientKeyExchange.h \
			include/tls/ConnectionState.h include/tls/ExtensionManager.h include/tls/Finished.h \
			include/tls/HandshakeBody.h include/tls/HandshakeRecord.h \
			include/tls/PGPCertificate.h include/tls/Plaintext.h include/tls/RecordProtocol.h \
			include/tls/ServerCertificate.h include/tls/ServerHello.h \
			include/tls/ServerKeyExchange.h
TLS_SOURCE= $(TLS_OBJECT:.o=.cc)

CKOBJECT= $(CIPHER_OBJECT) $(CIPHERMODES_OBJECT) $(DATA_OBJECT) \
		  $(DIGEST_OBJECT) $(KEYS_OBJECT) $(MAC_OBJECT) $(RANDOM_OBJECT) \
		  $(SIGNATURE_OBJECT)

TLSOBJECT= $(TLS_OBJECT)

PGPOBJECT= $(OPENPGP_OBJECT)

ifeq ($(UNAME), Darwin)
CKLIBRARY= libcryptokitty.dylib
TLSLIBRARY= libcktls.dylib
PGPLIBRARY= libckpgp.dylib
endif
ifeq ($(UNAME), Linux)
CKLIBRARY= libcryptokitty.so
TLSLIBRARY= libcktls.so
PGPLIBRARY= libckpgp.so
endif

.SUFFIXES:

.PHONY: clean install

all: $(CKLIBRARY) $(PGPLIBRARY) $(TLSLIBRARY)

$(CIPHER_OBJECT): $(CIPHER_SOURCE) $(CIPHER_HEADER)
	$(MAKE) -C cipher

$(CIPHERMODES_OBJECT): $(CIPHERMODES_SOURCE) $(CIPHERMODES_HEADER)
	$(MAKE) -C ciphermodes

$(DATA_OBJECT): $(DATA_SOURCE) $(DATA_HEADER)
	$(MAKE) -C data

$(DIGEST_OBJECT): $(DIGEST_SOURCE) $(DIGEST_HEADER)
	$(MAKE) -C digest

$(KEYS_OBJECT): $(KEYS_SOURCE) $(KEYS_HEADER)
	$(MAKE) -C keys

$(MAC_OBJECT): $(MAC_SOURCE) $(MAC_HEADER)
	$(MAKE) -C mac

$(RANDOM_OBJECT): $(RANDOM_SOURCE) $(RANDOM_HEADER)
	$(MAKE) -C random

$(SIGNATURE_OBJECT): $(SIGNATURE_SOURCE) $(SIGNATURE_HEADER)
	$(MAKE) -C signature

$(TLS_OBJECT): $(TLS_SOURCE) $(TLS_HEADER)
	$(MAKE) -C tls

$(OPENPGP_OBJECT): $(OPENPGP_SOURCE) $(OPENPGP_HEADER)
	$(MAKE) -C openpgp

$(CKLIBRARY): $(CKOBJECT)
	    $(LD) -o $@ $(CKOBJECT) $(LDFLAGS) $(CK_LDPATHS) $(CK_LDLIBS)

$(TLSLIBRARY): $(TLSOBJECT)
	    $(LD) -o $@ $(TLSOBJECT) $(LDFLAGS) $(TLS_LDPATHS) $(TLS_LDLIBS)

$(PGPLIBRARY): $(PGPOBJECT)
	    $(LD) -o $@ $(PGPOBJECT) $(LDFLAGS) $(PGP_LDPATHS) $(PGP_LDLIBS)

install: $(LIBRRY)
	rm -rf $(CK_INCLUDE)
	cp $(CKLIBRARY) $(DEV_HOME)/lib
	cp $(TLSLIBRARY) $(DEV_HOME)/lib
	cp $(PGPLIBRARY) $(DEV_HOME)/lib
	cp -af include/cipher $(CK_INCLUDE)
	cp -af include/ciphermodes $(CK_INCLUDE)
	cp -af include/data $(CK_INCLUDE)
	cp -af include/digest $(CK_INCLUDE)
	cp -af include/exceptions $(CK_INCLUDE)
	cp -af include/cipher $(CK_INCLUDE)
	cp -af include/keys $(CK_INCLUDE)
	cp -af include/mac $(CK_INCLUDE)
	cp -af include/random $(CK_INCLUDE)
	cp -af include/signature $(CK_INCLUDE)
	cp -af include/tls $(CK_INCLUDE)
	cp -af include/openpgp $(CK_INCLUDE)

clean:
	rm -f $(CKLIBRARY) $(TLSLIBRARY) $(PGPLIBRARY)
	cd cipher && $(MAKE) clean
	cd ciphermodes && $(MAKE) clean
	cd data && $(MAKE) clean
	cd digest && $(MAKE) clean
	cd keys && $(MAKE) clean
	cd mac && $(MAKE) clean
	cd random && $(MAKE) clean
	cd signature && $(MAKE) clean
	cd tls && $(MAKE) clean
	cd openpgp && $(MAKE) clean

