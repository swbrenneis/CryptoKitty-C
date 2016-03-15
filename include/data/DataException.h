#ifndef DATAEXCEPTION_H_INCLUDED
#define DATAEXCEPTION_H_INCLUDED

#include <string>

class DataException {

    protected:
        DataException() {}

    public:
        DataException(const std::string& msg) : message(msg) {}
        DataException(const RNGException& other)
                : message(other.message) {}
        ~DataException() {}

    public:
        const std::string& getMessage() const { return message; }

    private:
        std::string message;

};

#endif // DATAEXCEPTION_H_INCLUDED
