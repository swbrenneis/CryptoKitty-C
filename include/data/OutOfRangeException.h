#ifndef OUTOFRANGEEXCEPTION_H_INCLUDED
#define OUTOFRANGEEXCEPTION_H_INCLUDED

#include "DataException.h"

class OutOfRangeException : public DataException {

    protected:
        OutOfRangeException() {}

    public:
        OutOfRangeException(const std::string& msg)
                : DataException(msg) {}
        OutOfRangeException(const OutOfRangeException& other)
                : DataException(other) {}
        ~OutOfRangeException() {}

};

#endif // DATAOUTOFRANGEEXCEPTION_H_INCLUDED
