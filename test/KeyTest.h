#ifndef KEYTEST_H_INCLUDED
#define KEYTEST_H_INCLUDED

class KeyTest {

    public:
        KeyTest();
        ~KeyTest();

    private:
        KeyTest(const KeyTest& other);
        KeyTest& operator= (const KeyTest& other);

    public:
        bool DHtest(int keysize);

};

#endif  // KEYTEST_H_INCLUDED
