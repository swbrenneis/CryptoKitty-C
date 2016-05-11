#include "tls/Plaintext.h"
#include "tls/HandshakeRecord.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned16.h"

namespace CKTLS {

Plaintext::Plaintext()
: RecordProtocol(application_data) {
}

Plaintext::~Plaintext() {
}

}
