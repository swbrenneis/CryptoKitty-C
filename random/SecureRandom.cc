#include "../include/random/SecureRandom.h"
#include "../include/random/BBSSecureRandom.h"
#include "../include/random/SecureRandomException.h"
#include <sstream>

SecureRandom::SecureRandom() {
}

SecureRandom::~SecureRandom() {
}

SecureRandom*
SecureRandom::getSecureRandom(const std::string& name) {

    if (name == "BBS") {
        return new BBSSecureRandom;
    }

    std::ostringstream msg;
    msg << "Invalid secure random name: " << name;
    throw SecureRandomException(msg.str());

}
