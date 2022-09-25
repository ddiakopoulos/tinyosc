// This software is in the public domain. Where that dedication is not recognized, you
// are granted a perpetual, irrevocable license to copy, distribute, and modify this
// file as you see fit. Based on zed_net (https://github.com/Smilex/zed_net)
// The features implemented here are not thread-safe. 

#pragma once

#ifndef tinyosc_net_hpp
#define tinyosc_net_hpp

#include <string>
#include <assert.h>
#include <cstring>
#include <limits>

#if (defined(__linux) || defined(__unix) || defined(__posix) || defined(__LINUX__) || defined(__linux__))
    #define PLATFORM_LINUX
#elif (defined(_WIN64) || defined(_WIN32) || defined(__CYGWIN32__) || defined(__MINGW32__))
    #define PLATFORM_WINDOWS
#elif (defined(MACOSX) || defined(__DARWIN__) || defined(__APPLE__))
    #define PLATFORM_MACOS
#endif

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
    #define OSC_NET_BSD_SOCKETS
#endif

// struct for parsing OSC urls, such as: osc.udp://foobar:9999/foo/plop/
struct osc_url
{
    std::string protocol;
    std::string hostname;
    std::string port;
    std::string path;
    int32_t the_error {0};

    osc_url() = default;
    osc_url(const std::string & url) { init(url); }
    bool check_error() const { return the_error == 0; }
    bool init(const std::string & url)
    {
        the_error = 0;
        const char * s = url.c_str();
        const char * prot = strstr(s, "osc.");
        if (prot == 0)
        {
            protocol = "udp";
        }
        else
        {
            const char * p2 = strstr(prot, "://");
            if (p2)
            {
                protocol.assign(prot + 4, p2);
            }
            else
            {
                the_error = 1;
                return false;
            }
            s = p2 + 3;
        }
        const char * po = strstr(s, ":");
        if (!po)
        {
            the_error = 2;
            return false;
        }
        hostname.assign(s, po);
        s = po + 1;

        const char * pa = strstr(s, "/");
        if (!pa)
        {
            port = s;
            path = "/";
        }
        else
        {
            port.assign(s, pa);
            path = pa;
        }
        return true;
    }
};

#ifdef __cplusplus
extern "C"
{
#endif

    ///////////////////////////////////////////////
    //    Network Static Lifecycle Management    //
    ///////////////////////////////////////////////

    // Get a brief reason for failure
    const char * osc_net_get_error(void);

    // Perform platform-specific socket initialization;
    // *must* be called before using any other function
    //
    // Returns 0 on success, -1 otherwise (call 'osc_net_get_error' for more info)
    int osc_net_init(void);

    // Perform platform-specific socket de-initialization;
    // *must* be called when finished using the other functions
    void osc_net_shutdown(void);

    #ifdef PLATFORM_WINDOWS
        typedef size_t osc_net_socket_handle_t;
    #else
        typedef int osc_net_socket_handle_t;
    #endif

    ////////////////////////////
    //    Internet Address    //
    ////////////////////////////

    // Represents an internet address usable by sockets
    typedef struct
    {
        uint32_t host;
        uint16_t port;
    } osc_net_address_t;

    // Obtain an address from a host name and a port
    //
    // 'host' may contain a decimal formatted IP (such as "127.0.0.1"), a human readable
    // name (such as "localhost"), or NULL for the default address
    //
    // Returns 0 on success, -1 otherwise (call 'osc_net_get_error' for more info)
    int osc_net_get_address(osc_net_address_t * address, const char * host, uint16_t port);

    // Converts an address's host name into a decimal formatted string
    //
    // Returns NULL on failure (call 'osc_net_get_error' for more info)
    const char * osc_net_host_to_str(unsigned int host);

    // Wraps the system handle for a UDP/TCP socket
    typedef struct
    {
        osc_net_socket_handle_t handle;
        uint64_t non_blocking;
        int ready;
    } osc_net_socket_t;

    // Closes a previously opened socket
    void osc_net_socket_close(osc_net_socket_t * socket);

    //////////////////////////
    //    UDP Socket API    //
    //////////////////////////

    // Opens a UDP socket and binds it to a specified port (use 0 to select a random open port)
    // If a hostname is provided, 
    //
    // Socket will not block if 'non-blocking' is non-zero
    //
    // Returns 0 on success
    // Returns -1 on failure (call 'osc_net_get_error' for more info)
    int osc_net_udp_socket_open(osc_net_socket_t * socket, const osc_net_address_t addr, uint64_t non_blocking);

    // Sends a specific amount of data to 'destination'
    // Returns 0 on success, -1 otherwise (call 'osc_net_get_error' for more info)
    int osc_net_udp_socket_send(osc_net_socket_t * socket, osc_net_address_t destination, const void * data, int size);

    // Receives a specific amount of data from 'sender'
    // Returns the number of bytes received, -1 otherwise (call 'osc_net_get_error' for more info)
    int osc_net_udp_socket_receive(osc_net_socket_t * socket, osc_net_address_t * sender, void * data, int size, int timeout_ms = 0);

    //////////////////////////
    //    TCP Socket API    //
    //////////////////////////

    // Opens a TCP socket and binds it to a specified port
    // (use 0 to select a random open port)
    //
    // Socket will not block if 'non-blocking' is non-zero
    //
    // Returns NULL on failure (call 'osc_net_get_error' for more info)
    // Socket will listen for incoming connections if 'listen_socket' is non-zero
    // Returns 0 on success
    // Returns -1 on failure (call 'osc_net_get_error' for more info)
    int osc_net_tcp_socket_open(osc_net_socket_t * socket, uint16_t port, uint64_t non_blocking, int listen_socket);

    // Connect to a remote endpoint
    // Returns 0 on success.
    //  if the socket is non-blocking, then this can return 1 if the socket isn't ready
    //  returns -1 otherwise. (call 'osc_net_get_error' for more info)
    int osc_net_tcp_connect(osc_net_socket_t * socket, osc_net_address_t remote_addr);

    // Accept connection
    // New remote_socket inherits non-blocking from listening_socket
    // Returns 0 on success.
    //  if the socket is non-blocking, then this can return 1 if the socket isn't ready
    //  if the socket is non_blocking and there was no connection to accept, returns 2
    //  returns -1 otherwise. (call 'osc_net_get_error' for more info)
    int osc_net_tcp_accept(osc_net_socket_t * listening_socket, osc_net_socket_t * remote_socket, osc_net_address_t * remote_addr);

    // Returns 0 on success.
    //  if the socket is non-blocking, then this can return 1 if the socket isn't ready
    //  returns -1 otherwise. (call 'osc_net_get_error' for more info)
    int osc_net_tcp_socket_send(osc_net_socket_t * remote_socket, const void * data, int size);

    // Returns 0 on success.
    //  if the socket is non-blocking, then this can return 1 if the socket isn't ready
    //  returns -1 otherwise. (call 'osc_net_get_error' for more info)
    int osc_net_tcp_socket_receive(osc_net_socket_t * remote_socket, void * data, int size);

    // Blocks until the TCP socket is ready. Only makes sense for non-blocking socket.
    // Returns 0 on success.
    //  returns -1 otherwise. (call 'osc_net_get_error' for more info)
    int osc_net_tcp_make_socket_ready(osc_net_socket_t * socket);

#ifdef __cplusplus
}
#endif

#endif  // tinyosc_net_hpp

#ifdef OSC_NET_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef PLATFORM_WINDOWS

    #ifdef OSC_NET_IGNORE_DEPRECATION_WARNINGS
        #define _WINSOCK_DEPRECATED_NO_WARNINGS  // This "fix" prevents deprecated warnings!
    #endif

    #include <WinSock2.h>
    #include <ws2tcpip.h>  //required by getaddrinfo()
    #pragma comment(lib, "wsock32.lib")

    #define OSC_NET_SOCKET_ERROR SOCKET_ERROR
    #define OSC_NET_INVALID_SOCKET INVALID_SOCKET

    typedef int socklen_t;

#else

    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>

    #define OSC_NET_SOCKET_ERROR -1
    #define OSC_NET_INVALID_SOCKET -1

#endif

static const char * osc_net__g_error;

static int osc_net__error(const char * message)
{
    osc_net__g_error = message;
    return -1;
}

const char * osc_net_get_error(void)
{
    return osc_net__g_error;
}

int osc_net_init(void)
{
#ifdef PLATFORM_WINDOWS
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return osc_net__error("Windows Sockets failed to start");
#endif
    return 0;
}

void osc_net_shutdown(void)
{
#ifdef PLATFORM_WINDOWS
    WSACleanup();
#endif
}

addrinfo init_hints(const int flags)
{
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = flags;
    return hints;
}

// https://github.com/gbudiman/netsocket/blob/8db1688600bec5b80cbdc5fe248d795f171a63fe/Socket.cpp
// https://github.com/itsdrell/SoftwareDevelopment/blob/88d73709933da11e3be3a86795ccdff027ef8b44/Engine/Code/Engine/Net/NetAddress.cpp
// https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-gethostbyname
int osc_net_get_address(osc_net_address_t * address, const char * host, uint16_t port)
{
    addrinfo hints = init_hints(AI_PASSIVE);

    if (host == nullptr)
    {
        address->host = INADDR_ANY;
    }
    else
    {
        address->host = inet_addr(host);
        if (address->host == INADDR_NONE)
        {
            struct hostent * hostent = gethostbyname(host); // @fixme - replace with getaddrinfo()
            if (hostent)
            {
                std::memcpy(&address->host, hostent->h_addr, hostent->h_length);
            }
            else
            {
                return osc_net__error("Invalid host name");
            }
        }
    }

    address->port = port;

    return 0;
}

const char * osc_net_host_to_str(unsigned int host)
{
    struct in_addr in;
    in.s_addr = host;
    return inet_ntoa(in);
}

#include <iostream>

int osc_net_udp_socket_open(osc_net_socket_t * sock, const osc_net_address_t addr, uint64_t non_blocking)
{
    if (!sock)
    {        
        return osc_net__error("Socket is NULL");
    }

    // Create the socket
    sock->handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->handle <= 0)
    {
        osc_net_socket_close(sock);
        return osc_net__error("Failed to create socket");
    }

    // Bind the socket to the port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = addr.host; // either INADDR_ANY or 0
    address.sin_port = htons(addr.port);

    // Listen only (AI_PASSIVE)
    if (addr.host == INADDR_ANY)
    {
        if (bind(sock->handle, (const struct sockaddr *) &address, sizeof(struct sockaddr_in)) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to bind socket (INADDR_ANY)");
        }
    }
    else
    {
        // Send
        if (connect(sock->handle, (const struct sockaddr *) &address, sizeof(struct sockaddr_in)) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to connect socket (addr.host)");
        }
        else
        {   
            // @todo - success
            //assert((size_t) rp->ai_addrlen <= sizeof remote_addr);
            //std::memcpy(&remote_addr.addr(), rp->ai_addr, rp->ai_addrlen);
        }
    }

    // Set the socket to non-blocking if neccessary
    if (non_blocking)
    {
#ifdef PLATFORM_WINDOWS
        u_long arg = (u_long) non_blocking;
        if (ioctlsocket(sock->handle, FIONBIO, &arg) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to set socket to non-blocking");
        }
#else
        if (fcntl(sock->handle, F_SETFL, O_NONBLOCK, non_blocking) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to set socket to non-blocking");
        }
#endif
    }

    sock->non_blocking = non_blocking;

    return 0;
}

int osc_net_tcp_socket_open(osc_net_socket_t * sock, uint16_t port, uint64_t non_blocking, int listen_socket)
{
    if (!sock)
        return osc_net__error("Socket is NULL");

    // Create the socket
    sock->handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock->handle <= 0)
    {
        osc_net_socket_close(sock);
        return osc_net__error("Failed to create socket");
    }

    // Bind the socket to the port
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock->handle, (const struct sockaddr *) &address, sizeof(struct sockaddr_in)) != 0)
    {
        osc_net_socket_close(sock);
        return osc_net__error("Failed to bind socket");
    }

    // Set the socket to non-blocking if neccessary
    if (non_blocking)
    {
#ifdef PLATFORM_WINDOWS
        u_long arg = (u_long) non_blocking;
        if (ioctlsocket(sock->handle, FIONBIO, &arg) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to set socket to non-blocking");
        }
#else
        if (fcntl(sock->handle, F_SETFL, O_NONBLOCK, non_blocking) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed to set socket to non-blocking");
        }
#endif
        sock->ready = 0;
    }

    if (listen_socket)
    {
        if (listen(sock->handle, SOMAXCONN) != 0)
        {
            osc_net_socket_close(sock);
            return osc_net__error("Failed make socket listen");
        }
    }
    sock->non_blocking = non_blocking;

    return 0;
}

// Returns 1 if it would block, < 0 if there's an error.
int osc_net_check_would_block(osc_net_socket_t * socket)
{
    struct timeval timer;
    fd_set writefd;
    int retval;

    if (socket->non_blocking && !socket->ready)
    {
        FD_ZERO(&writefd);
        FD_SET(socket->handle, &writefd);
        timer.tv_sec = 0;
        timer.tv_usec = 0;
        retval = select(0, NULL, &writefd, NULL, &timer);
        if (retval == 0)
            return 1;
        else if (retval == OSC_NET_SOCKET_ERROR)
        {
            osc_net_socket_close(socket);
            return osc_net__error("Got socket error from select()");
        }
        socket->ready = 1;
    }

    return 0;
}

int osc_net_tcp_make_socket_ready(osc_net_socket_t * socket)
{
    if (!socket->non_blocking) return 0;
    if (socket->ready) return 0;

    fd_set writefd;
    int retval;

    FD_ZERO(&writefd);
    FD_SET(socket->handle, &writefd);
    retval = select(0, NULL, &writefd, NULL, NULL);
    if (retval != 1)
        return osc_net__error("Failed to make non-blocking socket ready");

    socket->ready = 1;

    return 0;
}

int osc_net_tcp_connect(osc_net_socket_t * socket, osc_net_address_t remote_addr)
{
    struct sockaddr_in address;
    int retval;

    if (!socket) return osc_net__error("Socket is NULL");

    retval = osc_net_check_would_block(socket);

    if (retval == 1) return 1;
    else if (retval) return -1;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = remote_addr.host;
    address.sin_port = htons(remote_addr.port);

    retval = connect(socket->handle, (const struct sockaddr *) &address, sizeof(address));
    if (retval == OSC_NET_SOCKET_ERROR)
    {
        osc_net_socket_close(socket);
        return osc_net__error("Failed to connect socket");
    }

    return 0;
}

int osc_net_tcp_accept(osc_net_socket_t * listening_socket, osc_net_socket_t * remote_socket, osc_net_address_t * remote_addr)
{
    struct sockaddr_in address;
    int retval, handle;

    if (!listening_socket) return osc_net__error("Listening socket is NULL");
    if (!remote_socket)    return osc_net__error("Remote socket is NULL");
    if (!remote_addr)      return osc_net__error("Address pointer is NULL");

    retval = osc_net_check_would_block(listening_socket);
    if (retval == 1) return +1;
    else if (retval) return -1;

#ifdef PLATFORM_WINDOWS
    typedef int socklen_t;
#endif

    socklen_t addrlen = sizeof(address);
    handle = accept(listening_socket->handle, (struct sockaddr *) &address, &addrlen);

    if (handle == OSC_NET_INVALID_SOCKET) return 2;

    remote_addr->host = address.sin_addr.s_addr;
    remote_addr->port = ntohs(address.sin_port);
    remote_socket->non_blocking = listening_socket->non_blocking;
    remote_socket->ready = 0;
    remote_socket->handle = handle;

    return 0;
}

void osc_net_socket_close(osc_net_socket_t * socket)
{
    if (!socket)
    {
        return;
    }

    if (socket->handle && socket->handle != OSC_NET_INVALID_SOCKET)
    {
#ifdef PLATFORM_WINDOWS
        closesocket(socket->handle);
#else
        close(socket->handle);
#endif
        socket->handle = OSC_NET_INVALID_SOCKET;
    }
}

int osc_net_udp_socket_send(osc_net_socket_t * socket, osc_net_address_t destination, const void * data, int size)
{
    if (!socket)
    {
        return osc_net__error("Socket is NULL");
    }

    if (socket->handle == OSC_NET_INVALID_SOCKET)
    {
        return osc_net__error("Socket is invalid");
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = destination.host;
    address.sin_port = htons(destination.port);

    int sent_bytes = sendto(socket->handle, (const char *) data, size, 0, (const struct sockaddr *) &address, sizeof(struct sockaddr_in));
    if (sent_bytes != size)
    {
        return osc_net__error("Failed to send buffer");
    }

    return 0;
}

int osc_net_udp_socket_receive(osc_net_socket_t * socket, osc_net_address_t * sender, void * data, int size, int timeout_ms)
{
    if (!socket)
    {
        return osc_net__error("Socket is NULL");
    }
    if (socket->handle == OSC_NET_INVALID_SOCKET)
    {
        return osc_net__error("Socket is invalid");
    }

    // check if something is available
    // if (timeout_ms >= 0)
    // {
    //     struct timeval tv;
    //     memset(&tv, 0, sizeof tv);
    //     tv.tv_sec = timeout_ms / 1000;
    //     tv.tv_usec = (timeout_ms % 1000) * 1000;
    // 
    //     fd_set readset;
    //     FD_ZERO(&readset);
    //     FD_SET(socket->handle, &readset);
    // 
    //     int ret = select(socket->handle + 1, &readset, 0, 0, &tv);
    //     if (ret <= 0)
    //     {  
    //         return 0;
    //     }
    // }

    struct sockaddr_in from;
    socklen_t from_length = sizeof(from);

    int received_bytes = recvfrom(socket->handle, (char *) data, size, 0, (struct sockaddr *) &from, &from_length);

    if (received_bytes < 0)
    {
        // EAGAIN/EINTR/EWOULDBLOCK are only informative (recoverable) conditions
#ifdef PLATFORM_WINDOWS
        if (WSAGetLastError() != WSAEINTR && WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAECONNRESET && WSAGetLastError() != WSAECONNREFUSED)
        {
            char s[512];
            _snprintf_s(s, 512, 512, "system error #%d", WSAGetLastError());
            std::cout << "what error? " << std::string(s) << std::endl;
            return osc_net__error(s);
        }
#endif
        return false;
    }

    sender->host = from.sin_addr.s_addr;
    sender->port = ntohs(from.sin_port);

    return received_bytes;  // no error
}

int osc_net_tcp_socket_send(osc_net_socket_t * remote_socket, const void * data, int size)
{
    int retval;

    if (!remote_socket)
    {
        return osc_net__error("Socket is NULL");
    }

    retval = osc_net_check_would_block(remote_socket);
    if (retval == 1)
        return 1;
    else if (retval)
        return -1;

    int sent_bytes = send(remote_socket->handle, (const char *) data, size, 0);
    if (sent_bytes != size)
    {
        return osc_net__error("Failed to send buffer");
    }

    return 0;
}

int osc_net_tcp_socket_receive(osc_net_socket_t * remote_socket, void * data, int size)
{
    int retval;

    if (!remote_socket)
    {
        return osc_net__error("Socket is NULL");
    }

    retval = osc_net_check_would_block(remote_socket);

    if (retval == 1) return 1;
    else if (retval) return -1;

    int received_bytes = recv(remote_socket->handle, (char *) data, size, 0);
    if (received_bytes <= 0)
    {
        return 0;
    }
    return received_bytes;
}

#endif  // OSC_NET_IMPLEMENTATION
