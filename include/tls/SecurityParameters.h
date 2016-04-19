#ifndef SECURITYPARAMETERS_H_INCLUDED
#define SECURITYPARAMETERS_H_INCLUDED

#include "cthread/ThreadLocal.h"

namespace CKTLS {

class SecurityParameters : public ThreadLocal {

    public:
        SecurityParameters();
        ~SecurityParameters();

    private:
        SecurityParameters(const SecurityParameters& other);
        SecurityParameters& operator= (const SecurityParameters& other);

    public:
        static SecurityParameters *getParameters();

};

}

#endif  // SECURITYPARAMETERS_H_INCLUDED
