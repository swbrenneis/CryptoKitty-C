#ifndef DIGEST_H_INCLUDED
#define DIGEST_H_INCLUDED

#include <string>

namespace CK {

class ByteArray;

/*
 * Abstract base class for all digests and hashes.
 */
class Digest {

    protected:
        Digest() {}

    private:
        Digest(const Digest& other);
        Digest& operator= (const Digest& other);

    public:
        virtual ~Digest() {}

    public:
        virtual ByteArray digest()=0;
        virtual ByteArray digest(const ByteArray& bytes)=0;
        virtual unsigned getBlockSize() const=0; // Used for HMAC
        virtual const ByteArray& getDER() const=0;
        virtual unsigned getDigestLength() const=0;
        virtual void reset()=0;
        virtual void update(unsigned char byte)=0;
        virtual void update(const ByteArray& bytes)=0;
        virtual void update(const ByteArray& bytes, unsigned offset,
                                        unsigned length)=0;

    public:
        static Digest *getInstance(const std::string& algorithm);

    protected:
        virtual ByteArray finalize(const ByteArray& bytes)=0;

};

}

#endif  // DIGEST_H_INCLUDED
