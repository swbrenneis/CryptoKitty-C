#ifndef SecureRandomEXCEPTION_H_INCLUDED
#define SecureRandomEXCEPTION_H_INCLUDED

#include <string>

namespace CK {

class SecureRandomException {

    protected:
        SecureRandomException() {}

    public:
        SecureRandomException(const std::string& msg) : message(msg) {}
        SecureRandomException(const SecureRandomException& other)
                : message(other.message) {}
        ~SecureRandomException() {}

    public:
        const std::string& getMessage() const { return message; }

    private:
        std::string message;

};

}

#endif // SecureRandomEXCEPTION_H_INCLUDED
