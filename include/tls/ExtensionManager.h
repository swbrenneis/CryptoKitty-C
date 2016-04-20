#ifndef EXTENSIONMANAGER_H_INCLUDED
#define EXTENSIONMANAGER_H_INCLUDED

#include "data/ByteArray.h"
#include "data/Unsigned16.h"
#include <deque>
#include <map>
#include <iostream>

namespace CKTLS {

struct Extension {
    CK::Unsigned16 type;
    CK::ByteArray data;
};

typedef std::deque<Extension> ExtensionList;
typedef ExtensionList::const_iterator ExtConstIter;

// Some extension enumerators

// Elliptic curve types.
enum NamedCurve { sect163k1=1, sect163r1=2, sect163r2=3, sect193r1=4,
                    sect193r2=5, sect233k1=6, sect233r1=7, sect239k1=8,
                    sect283k1=9, sect283r1=10, sect409k1=11, sect409r1=12,
                    sect571k1=13, sect571r1=14, secp160k1=15, secp160r1=16,
                    secp160r2=17, secp192k1=18, secp192r1=19, secp224k1=20,
                    secp224r1=21, secp256k1=22, secp256r1=23, secp384r1=24,
                    secp521r1=25, arbitrary_explicit_prime_curves=0xFF01,
                    arbitrary_explicit_char2_curves=0xFF02 };

// Signature hash algorithms.
enum HashAlgorithm { none=0, md5=1, sha1=2, sha224=3, sha256=4, sha384=5, sha512=6 };

enum SignatureAlgorithm { anonymous=0, rsa=1, dsa=2, ecdsa=3 };

struct SignatureAndHashAlgorithm {
    HashAlgorithm hash;
    SignatureAlgorithm signature;
};

// Certificate types

enum CertificateType { x_509=0, openpgp=1 };

class ExtensionManager {

    public:
        ExtensionManager();
        ~ExtensionManager();

    private:
        ExtensionManager(const ExtensionManager& other);
        ExtensionManager& operator= (const ExtensionManager& other);

    public:
        void debugOut(std::ostream& out) const;
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;
        bool getExtension(Extension& ext, uint16_t etype) const;
        void loadDefaults();
        void setExtension(const Extension& ext);

    public:
        static const uint16_t CERT_TYPE;
        static const uint16_t NAMED_CURVES;

    private:
        typedef std::map<uint32_t, Extension> ExtensionMap;
        typedef ExtensionMap::const_iterator ExtConstIter;
        ExtensionMap extensions;

};

}

#endif  // EXTENSIONMANAGER_H_INCLUDED
