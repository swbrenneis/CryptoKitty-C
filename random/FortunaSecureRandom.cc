#include "random/FortunaSecureRandom.h"
#include "random/FortunaGenerator.h"
#include "coder/Unsigned64.h"
#include "coder/Unsigned32.h"
#include "exceptions/SecureRandomException.h"
#include <fstream>
#include <memory>
#include <cmath>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace CK {

FortunaGenerator *FortunaSecureRandom::gen = new FortunaGenerator;
bool FortunaSecureRandom::standalone = false;

static std::string socketPath("/var/fortuna/rnd");

FortunaSecureRandom::FortunaSecureRandom() {
}

FortunaSecureRandom::~FortunaSecureRandom() {
}

void FortunaSecureRandom::nextBytes(coder::ByteArray& bytes) {

    uint32_t length = bytes.getLength();
    uint32_t offset = 0;
    uint32_t limit = 0x100000;    // Length limited to 2**20 by generator
    coder::ByteArray rbytes;
    while (length > 0) {
        rbytes.clear();
        uint32_t count = std::min(length, limit);
        uint32_t read;
        if (standalone) {
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
uint32_t FortunaSecureRandom::nextInt() {

    coder::ByteArray bytes(4);
    nextBytes(bytes);
    coder::Unsigned32 u32(bytes);
    return u32.getValue();

}

/*
 * Returns the next 64 bits of entropy.
 */
uint64_t FortunaSecureRandom::nextLong() {

    coder::ByteArray bytes(8);
    nextBytes(bytes);
    coder::Unsigned64 u64(bytes);
    return u64.getValue();

}

uint32_t FortunaSecureRandom::readBytes(coder::ByteArray& bytes, uint32_t count) const {

    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path)-1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        throw SecureRandomException("Fortuna: Unable to open stream");
    }

    int res = connect(fd,reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (res < 0) {
        close(fd);
        throw SecureRandomException("Fortuna: Unable to open stream");
    }

    coder::Unsigned32 u32(count);
    std::unique_ptr<uint8_t> wbuf(u32.getEncoded(coder::bigendian).asArray());
    res = send(fd, wbuf.get(), 4, 0);
    if (res != 4) {
        close(fd);
        throw SecureRandomException("Fortuna: Unable to send stream");
    }

    std::unique_ptr<uint8_t> rbuf(new uint8_t[count]);
    uint32_t read = 0;
    while (read < count) {
        res = recv(fd, rbuf.get(), count, 0);
        if (res < 0) {
            close(fd);
            throw SecureRandomException("Fortuna: Unable to read stream");
        }
        if (res == 0) {     // Best effort.
            bytes.append(rbuf.get(), read);
            close(fd);
            return read;
        }
        read += res;
    }

    bytes.append(rbuf.get(), count);
    close(fd);

    return count;
}

void FortunaSecureRandom::setStandalone(bool s) {

    standalone = s;
    if (!standalone) {
        gen->start();
    }

}

}

