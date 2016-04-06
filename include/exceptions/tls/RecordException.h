#ifndef RECORDEXCEPTION_H_INCLUDED
#define RECORDEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CKTLS {

class RecordException : public CK::Exception {

    protected:
        RecordException() {}

    public:
        RecordException(const std::string& msg) : CK::Exception(msg) {}
        RecordException(const CK::Exception& other)
                : CK::Exception(other) {}

    private:
        RecordException& operator= (const RecordException& other);

    public:
        virtual ~RecordException() {}

};

}

#endif // RECORDEXCEPTION_H_INCLUDED
