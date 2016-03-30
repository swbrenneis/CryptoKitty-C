#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <cstdint>

namespace CK {

class ByteArray;

class AES {

   public:
       enum KeySize { AES128=16, AES192=24, AES256=32 };

    public:
        AES(KeySize ks);
        ~AES();

    private:
        AES(const AES& other);
        AES& operator= (const AES& other);

    private:
        struct StateArray {
            uint8_t row0[4];
            uint8_t row1[4];
            uint8_t row2[4];
            uint8_t row3[4];
        };

    private:
        void AddRoundKey(const StateArray& a, const StateArray& b,
                                        StateArray& c) const;
        void ExpandKey(const ByteArray& key, ByteArray& expandedKey) const;
        void KeyScheduleCore(ByteArray& w, int i) const;
        uint8_t RijndaelAdd(uint8_t a, uint8_t b) const;
        uint8_t RijndaelMultiply(uint8_t lhs, uint8_t rhs) const;
        void Rotate(ByteArray& word) const;
        void ShiftRow(const StateArray& a, StateArray& b) const;

    private:
        KeySize keySize;
        unsigned expandedKeySize;
        int Nk;
        int Nr;

        static const uint8_t Rcon[256];
        static const uint8_t Sbox[256];
        static const uint8_t InvSbox[256];

};

}

#endif  // AES_H_INCLUDED
