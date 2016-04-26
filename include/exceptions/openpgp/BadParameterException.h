#ifndef BADPARAMETEREXCEPTION_H_INCLUDED
#define BADPARAMETEREXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CKPGP {

class BadParameterException : public CK::Exception {

    protected:
        BadParameterException() {}

    public:
        BadParameterException(const std::string& msg) : CK::Exception(msg) {}
        BadParameterException(const CK::Exception& other)
                : CK::Exception(other) {}

    private:
        BadParameterException& operator= (const BadParameterException& other);

    public:
        virtual ~BadParameterException() {}

};

}

#endif // BADPARAMETEREXCEPTION_H_INCLUDED
