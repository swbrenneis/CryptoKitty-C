#ifndef MACTEST_H_INCLUDED
#define MACTEST_H_INCLUDED

class MACTest {

    public:
        MACTest();
        ~MACTest();

    private:
        MACTest(const MACTest&);
        MACTest& operator= (const MACTest&);

    public:
        bool HMACTest();

};

#endif  // MACTEST_H_INCLUDED
