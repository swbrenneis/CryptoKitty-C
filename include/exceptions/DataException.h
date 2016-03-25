#ifndef DATAEXCEPTION_H_INCLUDED
#define DATAEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class DataException : public Exception {

    protected:
        DataException() {}

    public:
        DataException(const std::string& msg) : Exception(msg) {}
        DataException(const DataException& other)
                : Exception(other) {}

    private:
        DataException& operator= (const DataException& other);

    public:
        virtual ~DataException() {}

};

}

#endif // DATAEXCEPTION_H_INCLUDED
