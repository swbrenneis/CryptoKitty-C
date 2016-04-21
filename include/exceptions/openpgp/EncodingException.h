#ifndef ENCODINGEXCEPTION_H_INCLUDED
#define ENCODINGEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CKPGP {

class EncodingException : public CK::Exception {

    protected:
        EncodingException() {}

    public:
        EncodingException(const std::string& msg) : CK::Exception(msg) {}
        EncodingException(const CK::Exception& other)
                : CK::Exception(other) {}

    private:
        EncodingException& operator= (const EncodingException& other);

    public:
        virtual ~EncodingException() {}

};

}

#endif // ENCODINGEXCEPTION_H_INCLUDED
