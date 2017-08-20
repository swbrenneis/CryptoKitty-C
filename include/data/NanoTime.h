#ifndef NANOTIME_H_INCLUDED
#define NANOTIME_H_INCLUDED

namespace CK {

/*
 * Convenience class for std::chrono functions
 */
class NanoTime {

    public:
        NanoTime();
        ~NanoTime() {}

    private:
        NanoTime(const NanoTime& other);
        NanoTime& operator =(const NanoTime& other);

    public:
        unsigned long getCurrentNanoseconds() const { return ntNanoseconds; }
        unsigned long getCurrentSeconds() const { return ntSeconds; }
        void newTime(); // Get new time value.

    private:
        unsigned long ntSeconds;
        unsigned long ntNanoseconds;

};

}

#endif // NANOTIME_H_INCLUDED
