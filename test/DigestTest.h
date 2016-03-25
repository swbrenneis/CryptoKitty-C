#ifndef DIGESTTEST_H_INCLUDED
#define DIGESTTEST_H_INCLUDED

class DigestTest {

    public:
        DigestTest();
        ~DigestTest();

    private:
        DigestTest(const DigestTest&);
        DigestTest& operator= (const DigestTest&);

    public:
        bool sha256Test();

};

#endif  // DIGESTTEST_H_INCLUDED
