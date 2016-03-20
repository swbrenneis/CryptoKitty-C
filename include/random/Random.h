#ifndef RANDOM_H_INCLUDED
#define RANDOM_H_INCLUDED

class ByteArray;

/*
 * Random number generator.
 * This class is largely unimplemented. It is intended
 * that there will be a subclass that provides the
 * actual PRNG.
 */
class Random {

    protected:
        Random();

    public:
        virtual ~Random();

    private:
        Random(const Random& other);
        Random& operator= (const Random& other);

    public:
        virtual void nextBytes(ByteArray& bytes);
        virtual int nextInt();
        virtual long nextLong();

    public:
        virtual void setSeed(unsigned long seedValue);

    protected:
        virtual unsigned long next(int bits);

};

#endif  // RANDOM_H_INCLUDED
