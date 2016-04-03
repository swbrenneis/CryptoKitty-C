#ifndef TCPCONNECTION_H_INCLUDED
#define TCPCONNECTION_H_INCLUDED

#include <cstdint>

namespace CK {

class TCPConnection {

    public:
        TCPConnection(uint16_t portnum);
        ~TCPConnection();

    private:
        TCPConnection(const TCPConnection& other);
        TCPConnection& operator= (const TCPConnection& other);

    public:
        void startListener();

    private:
        void createSocket();

    private:
        uint16_t port;
        int socket;
        bool runListener;

};

}

#endif  // TCPCONNECTION_H_INCLUDED
