#ifndef RADIX64_H_INCLUDED
#define RADIX64_H_INCLUDED

#include <string>
#include <sstream>
#include <cstdint>

namespace CK {
    class ByteArray;
}

namespace CKPGP {

/**
 * @author stevebrenneis
 *
 * Radix-64 encoding class. See RFC 4880, section 6.3.
 */
class Radix64 {

    protected:
        Radix64();

    public:
        ~Radix64();

    private:
        Radix64(const Radix64& other);
        Radix64& operator= (const Radix64& other);

    public:
        void decode(const CK::ByteArray& in, std::ostream& out) const;
	    uint32_t decodeCRC(const std::string& encoded) const;
	    void encode(const CK::ByteArray& in, std::ostream& out) const;
        std::string encodeCRC(uint32_t crcValue) const;

    private:
	    uint8_t findIndex(char letter) const;

    private:
	    static const std::string ALPHABET;

};

}
#endif  // RADIX64_H_INCLUDED
