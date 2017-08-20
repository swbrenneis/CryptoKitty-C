#include "data/NanoTime.h"
#include <chrono>

namespace CK {

NanoTime::NanoTime() {

     newTime();

}

void NanoTime::newTime() {

    using namespace std::chrono;
    auto current = steady_clock::now().time_since_epoch();
    ntSeconds = duration_cast<seconds>(current).count();
    ntNanoseconds = duration_cast<nanoseconds>(current).count();

}

}

