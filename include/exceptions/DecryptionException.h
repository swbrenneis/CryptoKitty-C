#ifndef DECRYPTIONEXCEPTION_H_INCLUDED
#define DECRYPTIONEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class DecryptionException : public Exception {

    public:
        // No oracles please.
        DecryptionException() : Exception("Decryption failed") {}
        DecryptionException(const Exception& other)
                : Exception(other) {}

    private:
        DecryptionException& operator= (const DecryptionException& other);

    public:
        virtual ~DecryptionException() {}

};

}

#endif // DECRYPTIONEXCEPTION_H_INCLUDED
