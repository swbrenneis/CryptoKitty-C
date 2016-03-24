#ifndef DATAEXCEPTION_H_INCLUDED
#define DATAEXCEPTION_H_INCLUDED

#include <string>

namespace CK {

class DataException {

    protected:
        DataException() {}

    public:
        DataException(const std::string& msg) : message(msg) {}
        DataException(const DataException& other)
                : message(other.message) {}
        virtual ~DataException() {}

    public:
        virtual const std::string& getMessage() const { return message; }

    private:
        std::string message;

};

}

#endif // DATAEXCEPTION_H_INCLUDED
