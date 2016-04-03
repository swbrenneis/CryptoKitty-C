#include "tls/TCPConnection.h"
#include "tls/TlsHandshake.h"
#include "exceptions/TCPException.h"
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

namespace CK {

TCPConnection::TCPConnection(uint16_t portnum):
: port(portnum),
  runListener(false)  {
}

TCPConnection::~TCPConnection() {
}

/*
 * Create a socket
 */
void TCPConnection::createSocket() {

    struct sockaddr_in name;

    // Create the socket.
    socket = ::socket(PF_INET, SOCK_STREAM, 0);
    if (socket < 0) {
        std::string err(strerror(errno));
        std::string label("Socket create error: ");
        throw TCPException(label+err);
    }

    // Give the socket a name.
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = htonl (INADDR_ANY);
    if (bind(socket,(struct sockaddr*)&name,sizeof (name)) < 0) {
        std::string err(strerror(errno));
        std::string label("Socket bind error: ");
        throw TCPException(label+err);
    }

}

/*
 * Caution - much C code ahead.
 */
void TCPConnection::startListener() {

    createSocket();
    if (listen(socket, 1) < 0) {
        std::string err(strerror(errno));
        std::string label("Socket listen error: ");
        throw TCPException(label+err);
    }


    /* Initialize the set of active sockets. */
    FD_ZERO (&active_fd_set);
    FD_SET (sock, &active_fd_set);

    while (runListener) {
        /* Block until input arrives on one or more active sockets. */
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, 0, 0, 0) < 0) {
            std::string err(strerror(errno));
            std::string label("Socket select error: ");
            throw TCPException(label+err);
        }

        /* Service all the sockets with input pending. */
        for (i = 0; i < FD_SETSIZE; ++i) {
            if (FD_ISSET (i, &read_fd_set)) {
                if (i == sock) {
                    /* Connection request on original socket. */
                    int new;
                    size = sizeof (clientname);
                    new = accept (sock, (struct sockaddr *) &clientname, &size);
                    if (new < 0) {
                        perror ("accept");
                        exit (EXIT_FAILURE);
                    }
                    fprintf (stderr,
                    "Server: connect from host %s, port %hd.\n",
                    inet_ntoa (clientname.sin_addr),
                    ntohs (clientname.sin_port));
                    FD_SET (new, &active_fd_set);
                }
                else {
                    /* Data arriving on an already-connected socket. */
                    if (read_from_client (i) < 0) {
                        close (i);
                        FD_CLR (i, &active_fd_set);
                    }
                }
            }
        }
    }
}


}
