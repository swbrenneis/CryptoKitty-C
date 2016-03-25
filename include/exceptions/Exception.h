#ifndef EXCEPTION_H_INCLUDED
#define EXCEPTION_H_INCLUDED

#include <string>

namespace CK {

class Exception {

    protected:
        Exception() {}
        Exception(const std::string& msg) : message(msg) {}
        Exception(const Exception& other)
                : message(other.message) {}

    private:
        Exception& operator= (const Exception& other);

    public:
        virtual ~Exception() {}

    public:
        virtual const std::string& getMessage() const { return message; }

    private:
        std::string message;

};

}

#endif // BADPARAMETEREXCEPTION_H_INCLUDED
