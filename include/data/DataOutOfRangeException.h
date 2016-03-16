#ifndef DATAOUTOFRANGEEXCEPTION_H_INCLUDED
#define DATAOUTOFRANGEEXCEPTION_H_INCLUDED

#include "DataException.h"

class DataOutOfRangeException : public DataException {

    protected:
        DataOutOfRangeException() {}

    public:
        DataOutOfRangeException(const std::string& msg)
                : DataException(msg) {}
        DataOutOfRangeException(const DataOutOfRangeException& other)
                : DataException(other) {}
        ~DataOutOfRangeException() {}

};

#endif // DATAOUTOFRANGEEXCEPTION_H_INCLUDED
