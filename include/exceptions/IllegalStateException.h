#ifndef ILLEGALSTATEEXCEPTION_H_INCLUDED
#define ILLEGALSTATEEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class IllegalStateException : public Exception {

    protected:
        IllegalStateException() {}

    public:
        IllegalStateException(const std::string& msg) : Exception(msg) {}
        IllegalStateException(const IllegalStateException& other)
                : Exception(other) {}

    private:
        IllegalStateException& operator= (const IllegalStateException& other);

    public:
        virtual ~IllegalStateException() {}

};

}

#endif // ILLEGALSTATEEXCEPTION_H_INCLUDED
