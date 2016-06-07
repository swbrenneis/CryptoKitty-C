#ifndef EXCEPTION_H_INCLUDED
#define EXCEPTION_H_INCLUDED

#include <exception>
#include <string>

namespace CK {

class Exception  : public std::exception {

    protected:
        Exception() {}
        Exception(const std::string& msg) : message(msg) {}
        Exception(const Exception& other)
                : message(other.message) {}

    private:
        Exception& operator= (const Exception& other);

    public:
        ~Exception() {}

    public:
        const char *what() const _GLIBCXX_USE_NOEXCEPT { return message.c_str(); }

    private:
        std::string message;

};

}

#endif // BADPARAMETEREXCEPTION_H_INCLUDED
