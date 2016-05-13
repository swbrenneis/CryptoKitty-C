#ifndef CIPHERTEXT_H_INCLUDED
#define CIPHERTEXT_H_INCLUDED

#include "tls/RecordProtocol.h"

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
        const coder::ByteArray& getPlaintext() const;
        void setPlaintext(const coder::ByteArray& plain);

    protected:
        void encode();
        void decode();

    private:
        coder::ByteArray plaintext;

};

}

#endif  // CIPHERTEXT_H_INCLUDED
