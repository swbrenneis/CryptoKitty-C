#include "random/FortunaSecureRandom.h"
#include "random/FortunaGenerator.h"
#include "coder/Unsigned64.h"
#include "coder/Unsigned32.h"
#include "exceptions/SecureRandomException.h"
#include <fstream>
#include <sstream>
#include <memory>
#include <cmath>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace CK {

FortunaGenerator *FortunaSecureRandom::gen = 0;
// Indicates whether the RNG is self-contained.
// If true, the random block generator is built into
// the object.
bool FortunaSecureRandom::standalone = false;

static const std::string FORTUNAPATH("/dev/fortuna");
static const size_t BUFSIZE = 512;      // Maximum read size of fortuna device.
static const uint32_t LIMIT = 0x100000;    // Length limited to 2**20 by generator

FortunaSecureRandom::FortunaSecureRandom() {
}

FortunaSecureRandom::~FortunaSecureRandom() {
}

void FortunaSecureRandom::nextBytes(coder::ByteArray& bytes) {

    uint32_t length = bytes.getLength();
    uint32_t offset = 0;
    coder::ByteArray rbytes;
    while (length > 0) {
        rbytes.clear();
        uint32_t count = std::min(length, LIMIT);
        uint32_t read;
        if (!standalone) {
            read = readBytes(rbytes, count);
        }
        else {
            gen->generateRandomData(rbytes, count);
            read = rbytes.getLength();
        }
        bytes.copy(offset, rbytes, 0, read);
        length -= read;
        offset += read;
    }

}

/*
 * Returns the next 32 bits of entropy.
 */
uint32_t FortunaSecureRandom::nextUnsignedInt() {

    coder::ByteArray bytes(4, 0);
    nextBytes(bytes);
    coder::Unsigned32 u32(bytes);
    return u32.getValue();

}

/*
 * Returns the next 64 bits of entropy.
 */
uint64_t FortunaSecureRandom::nextUnsignedLong() {

    coder::ByteArray bytes(8, 0);
    nextBytes(bytes);
    coder::Unsigned64 u64(bytes);
    return u64.getValue();

}

uint32_t FortunaSecureRandom::readBytes(coder::ByteArray& bytes, uint32_t count) const {

    std::unique_ptr<uint8_t[]> rbuf(new uint8_t[count]);
    char *cbuf = reinterpret_cast<char*>(rbuf.get());
    size_t toRead = count;
    if (toRead > BUFSIZE) {
        toRead = BUFSIZE;
    }
    std::ifstream rdev;
    std::filebuf *fbuf = rdev.rdbuf();
    fbuf->pubsetbuf(0, 0);
    rdev.open(FORTUNAPATH);
    if (rdev.good()) {
        rdev.read(cbuf, toRead);
    }
    rdev.close();

    /*int fd = open(FORTUNAPATH.c_str(), O_RDONLY);
    if (fd < 0) {
        std::ostringstream str;
        str << "Fortuna file open error: " << strerror(errno);
        throw SecureRandomException(str.str());
    }

    int readin = read(fd, cbuf, count);
    if (readin < 0) {
        std::ostringstream str;
        str << "Fortuna file read error: " << strerror(errno);
        throw SecureRandomException(str.str());
    }
    close(fd);*/

    bytes.append(rbuf.get(), toRead);
    return toRead;

}

void FortunaSecureRandom::setStandalone(bool s) {

    standalone = s;
    if (standalone) {
        gen = new FortunaGenerator;
        gen->start();
    }

}

}

