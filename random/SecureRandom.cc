#include "random/SecureRandom.h"
#include "random/BBSSecureRandom.h"
#include "random/FortunaSecureRandom.h"
#include "exceptions/SecureRandomException.h"
#include <sstream>

namespace CK {

SecureRandom::SecureRandom() {
}

SecureRandom::~SecureRandom() {
}

SecureRandom*
SecureRandom::getSecureRandom(const std::string& name) {

    if (name == "BBS") {
        return new BBSSecureRandom;
    }

    if (name == "Fortuna") {
        return new FortunaSecureRandom;
    }

    std::ostringstream msg;
    msg << "Invalid secure random name: " << name;
    throw SecureRandomException(msg.str());

}

}

