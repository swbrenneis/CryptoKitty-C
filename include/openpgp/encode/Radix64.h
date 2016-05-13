#ifndef RADIX64_H_INCLUDED
#define RADIX64_H_INCLUDED

#include <string>
#include <sstream>
#include <cstdint>

namespace coder {
    class ByteArray;
}

namespace CKPGP {

/**
 * @author stevebrenneis
 *
 * Radix-64 encoding class. See RFC 4880, section 6.3.
 */
class Radix64 {

    public:
        Radix64();
        ~Radix64();

    private:
        Radix64(const Radix64& other);
        Radix64& operator= (const Radix64& other);

    public:
        void decode(const coder::ByteArray& in, coder::ByteArray& out) const;
	    uint32_t decodeCRC(const std::string& encoded) const;
	    void encode(const coder::ByteArray& in, std::ostream& out) const;
        std::string encodeCRC(uint32_t crcValue) const;

    private:
        int sendColumn(char c, std::ostream& out, int column) const;

    private:
	    static const std::string ALPHABET;

};

}
#endif  // RADIX64_H_INCLUDED
