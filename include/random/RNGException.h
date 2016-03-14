#ifndef RNGEXCEPTION_H_INCLUDED
#define RNGEXCEPTION_H_INCLUDED

#include <string>

class RNGException {

    protected:
        RNGException() {}

    public:
        RNGException(const std::string& msg) : message(msg) {}
        RNGException(const RNGException& other)
                : message(other.message) {}
        ~RNGException() {}

    public:
        const std::string& getMessage() const { return message; }

    private:
        std::string message;

};

#endif // RNGEXCEPTION_H_INCLUDED
