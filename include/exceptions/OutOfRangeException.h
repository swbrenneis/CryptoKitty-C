#ifndef OUTOFRANGEEXCEPTION_H_INCLUDED
#define OUTOFRANGEEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class OutOfRangeException : public Exception {

    protected:
        OutOfRangeException() {}

    public:
        OutOfRangeException(const std::string& msg) : Exception(msg) {}
        OutOfRangeException(const OutOfRangeException& other)
                : Exception(other) {}

    private:
        OutOfRangeException& operator= (const OutOfRangeException& other);

    public:
        virtual ~OutOfRangeException() {}

};

}

#endif // OUTOFRANGEEXCEPTION_H_INCLUDED
