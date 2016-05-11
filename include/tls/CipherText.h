#ifndef CIPHERTEXT_H_INCLUDED
#define CIPHERTEXT_H_INCLUDED

#include "tls/RecordProtocol.h"
#include "data/ByteArray.h"

namespace CK {
    class CipherMode;
}

namespace CKTLS {

class CipherText : public RecordProtocol {

    public:
        CipherText();
        ~CipherText();

    private:
        CipherText(const CipherText& other);
        CipherText& operator= (const CipherText& other);

    public:
        const CK::ByteArray& getPlaintext() const;
        void setPlaintext(const CK::ByteArray& plain);

    protected:
        void encode();
        void decode();

    private:
        CK::ByteArray plaintext;

};

}

#endif  // CIPHERTEXT_H_INCLUDED
