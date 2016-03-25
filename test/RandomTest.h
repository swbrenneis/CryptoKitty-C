#ifndef RANDOMTEST_H_INCLUDED
#define RANDOMTEST_H_INCLUDED

class RandomTest {

    public:
        RandomTest();
        ~RandomTest();

    private:
        RandomTest(const RandomTest&);
        RandomTest& operator= (const RandomTest&);

    public:
        bool cmwcTest();
        bool BBSTest();

};

#endif  // RANDOMTEST_H_INCLUDED
