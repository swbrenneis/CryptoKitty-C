#ifndef DIGESTBASE_H_INCLUDED
#define DIGESTBASE_H_INCLUDED

#include "digest/Digest.h"
#include "data/ByteArray.h"
#include <string>

namespace CK {

/*
 * Digest base implementation class.
 * The class is abstract. Also includes a convenience method
 * for creating instances by name.
 */
class DigestBase : public Digest {

    protected:
        DigestBase();

    private:
        DigestBase(const DigestBase& other);
        DigestBase& operator= (const DigestBase& other);

    public:
        virtual ~DigestBase();

    public:
        ByteArray digest();
        ByteArray digest(const ByteArray& bytes);
        void reset();
        void update(unsigned char byte);
        void update(const ByteArray& bytes);
        void update(const ByteArray& bytes, unsigned offset, unsigned length);

    public:
        static Digest* getInstance(const std::string& algorithm);

    private:
        ByteArray accumulator;

};

}

#endif  // DIGESTBASE_H_INCLUDED
