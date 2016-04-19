#include "tls/SecurityParameters.h"

namespace CKTLS {

SecurityParameters::SecurityParameters() {
}

SecurityParameters::~SecurityParameters() {
}

SecurityParameters *SecurityParameters::getParameters() {

        return dynamic_cast<SecurityParameters*>(getLocal());

}

}

