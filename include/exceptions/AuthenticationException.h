#ifndef AUTHENTICATIONEXCEPTION_H_INCLUDED
#define AUTHENTICATIONEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class AuthenticationException : public Exception {

    protected:
        AuthenticationException() {}

    public:
        AuthenticationException(const std::string& msg) : Exception(msg) {}
        AuthenticationException(const Exception& other)
                : Exception(other) {}

    private:
        AuthenticationException& operator= (const AuthenticationException& other);

    public:
        virtual ~AuthenticationException() {}

};

}

#endif // AUTHENTICATIONEXCEPTION_H_INCLUDED
