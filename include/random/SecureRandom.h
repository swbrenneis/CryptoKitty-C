#ifndef SECURERANDOM_H_INCLUDED
#define SECURERANDOM_H_INCLUDED

#include "Random.h"
#include <string>

class SecureRandom : public Random {

    protected:
        SecureRandom();

    public:
        virtual ~SecureRandom();

    public:
        static SecureRandom* getSecureRandom(const std::string& name);

};

#endif	// SECURERANDOM_H_INCLUDED
