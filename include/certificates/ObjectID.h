#ifndef OBJECTID_H_INCLUDED
#define OBJECTID_H_INCLUDED

#include "certificates/Encodable.h"
#include <string>

namespace CK {

class ObjectID : public Encodable {

    protected:
        ObjectID();

    public:
        virtual ~ObjectID();

    private:
        ObjectID(const ObjectID& other);
        ObjectID& operator= (const ObjectID& other);

    public:
        typedef std::deque<uint32_t> OID;

    public:
        ByteArray encode() const;
        OID getObjectID() const;
        void setObjectID(const OID& oid);
        std::string toString() const;

    private:
        std::string oidString;
        OID oidValues;

};

}

#endif  // OBJECTID_H_INCLUDED
