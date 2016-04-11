#ifndef DIGEST_H_INCLUDED
#define DIGEST_H_INCLUDED

#include <string>
#include <cstdint>

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
        virtual uint32_t getBlockSize() const=0; // Used for HMAC
        virtual const ByteArray& getDER() const=0;
        virtual uint32_t getDigestLength() const=0;
        virtual void reset()=0;
        virtual void update(uint8_t byte)=0;
        virtual void update(const ByteArray& bytes)=0;
        virtual void update(const ByteArray& bytes, uint32_t offset,
                                        uint32_t length)=0;

    public:
        static Digest *getInstance(const std::string& algorithm);

    protected:
        virtual ByteArray finalize(const ByteArray& bytes)=0;

};

}

#endif  // DIGEST_H_INCLUDED
