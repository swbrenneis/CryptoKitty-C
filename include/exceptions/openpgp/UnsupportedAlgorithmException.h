#ifndef UNSUPPORTEDALGORITHMEXCEPTION_H_INCLUDED
#define UNSUPPORTEDALGORITHMEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CKPGP {

class UnsupportedAlgorithmException : public CK::Exception {

    protected:
        UnsupportedAlgorithmException() {}

    public:
        UnsupportedAlgorithmException(const std::string& msg) : CK::Exception(msg) {}
        UnsupportedAlgorithmException(const CK::Exception& other)
                : CK::Exception(other) {}

    private:
        UnsupportedAlgorithmException& operator= (const UnsupportedAlgorithmException& other);

    public:
        virtual ~UnsupportedAlgorithmException() {}

};

}

#endif // UNSUPPORTEDALGORITHMEXCEPTION_H_INCLUDED
