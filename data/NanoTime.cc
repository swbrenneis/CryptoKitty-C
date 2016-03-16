#include "../include/data/NanoTime.h"
#include "../include/data/DataException.h"
#include <time.h>

NanoTime::NanoTime() {

     newTime();

}

NanoTime::~NanoTime() {
}

unsigned long NanoTime::getFullTime() const {

    return time;

}

unsigned long NanoTime::getNanoseconds() const {

    return nanoseconds;

}

unsigned long NanoTime::getSeconds() const {

    return seconds;

}

void NanoTime::newTime() {

    timespec now;
    // We use CLOCK_MONOTONIC_RAW because it can't be
    // manipulated by settime, NTP, or adjtime
    int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    if (ret != 0) {
        throw DataException("NanoTime clock retrieval failed.");
    }
    time = (now.tv_sec * 1000000000) + now.tv_nsec;
    seconds = now.tv_sec;
    nanoseconds = now.tv_nsec;

}

