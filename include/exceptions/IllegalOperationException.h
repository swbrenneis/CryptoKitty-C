#ifndef ILLEGALOPERATIONEXCEPTION_H_INCLUDED
#define ILLEGALOPERATIONEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class IllegalOperationException : public Exception {

    protected:
        IllegalOperationException() {}

    public:
        IllegalOperationException(const std::string& msg) : Exception(msg) {}
        IllegalOperationException(const IllegalOperationException& other)
                : Exception(other) {}

    private:
        IllegalOperationException& operator= (const IllegalOperationException& other);

    public:
        virtual ~IllegalOperationException() {}

};

}

#endif // ILLEGALOPERATIONEXCEPTION_H_INCLUDED
