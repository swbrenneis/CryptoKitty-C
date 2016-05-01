#ifndef STRING2KEY_H_INCLUDED
#define STRING2KEY_H_INCLUDED

#include "data/ByteArray.h"

namespace CKPGP {

class String2Key {

    public:
        // Simple.
        String2Key(uint8_t alg);
        // Salted.
        String2Key(uint8_t alg, const CK::ByteArray& salt);
        // Salted and iterated.
        String2Key(uint8_t alg, const CK::ByteArray& salt, uint8_t count);
        ~String2Key();

    private:
        String2Key(const String2Key& other);
        String2Key& operator= (const String2Key& other);

    public:
        // Types
        static const uint8_t SIMPLE;
        static const uint8_t SALTED;
        static const uint8_t ITERSALT;

        //Hash algorithms.
        static const uint8_t MD5;
        static const uint8_t SHA1;
        static const uint8_t RIPEMD160;
        static const uint8_t SHA256;
        static const uint8_t SHA384;
        static const uint8_t SHA512;
        static const uint8_t SHA224;

    public:
        CK::ByteArray generateKey(const std::string& passphrase, unsigned bitsize) const;
        CK::ByteArray getSpecifier() const;

    private:
        uint8_t type;
        uint8_t algorithm;
        CK::ByteArray salt;
        uint8_t c;
        uint8_t count;

};

}

#endif  // STRING2KEY_H_INCLUDED
