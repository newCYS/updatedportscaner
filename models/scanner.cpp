#include "scanner.hpp"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
    typedef int socklen_t;
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <sys/select.h>
    #include <fcntl.h>
#endif

#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

// Convert enum to string
std::string port_state_to_string(PortState state) {
    switch (state) {
        case PortState::OPEN:
            return "OPEN";
        case PortState::CLOSED:
            return "CLOSED";
        case PortState::FILTERED:
            return "FILTERED";
        case PortState::ERROR_STATE:
            return "ERROR";
    }
    return "UNKNOWN";
}

// Get service name using system database
std::string port_to_service(int port) {
#ifdef _WIN32
    // On Windows, getservbyport might need WSAStartup
    servent *s = getservbyport(htons(static_cast<u_short>(port)), "tcp");
#else
    servent *s = getservbyport(htons(port), "tcp");
#endif
    if (s && s->s_name)
        return s->s_name;
    return "UNKNOWN";
}

void print_scan_results(const std::vector<Scanner> &scans,
                        int startPort, int endPort)
{
    const char* RESET   = "\033[0m";
    const char* GREEN   = "\033[32m";
    const char* RED     = "\033[31m";
    const char* YELLOW  = "\033[33m";
    const char* MAGENTA = "\033[35m";

    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(11) << "STATE"
              << std::setw(15) << "SERVICE"
              << "INFO\n";

    std::cout << "---------------------------------------------------------------\n";

    for (const auto &Scanner : scans) {
        if (Scanner.port < startPort || Scanner.port > endPort)
            continue;

        const char* stateColor = RESET;
        const char* infoColor  = RESET;

        if (Scanner.state == PortState::OPEN) {
            stateColor = GREEN;
            infoColor  = GREEN;
        }
        else if (Scanner.state == PortState::CLOSED) {
            stateColor = MAGENTA;
            infoColor  = MAGENTA;
        }
        else if (Scanner.state == PortState::FILTERED) {
            stateColor = YELLOW;
            infoColor  = YELLOW;
        }
        else if (Scanner.state == PortState::ERROR_STATE) {
            stateColor = RED;
            infoColor  = RED;
        }

        std::string stateStr = port_state_to_string(Scanner.state);
        std::string service  = port_to_service(Scanner.port);

        std::cout << std::left
                  << std::setw(8)  << Scanner.port
                  << std::setw(21) << (std::string(stateColor) + stateStr + RESET)
                  << std::setw(15) << service
                  << infoColor << Scanner.msg << RESET
                  << "\n";
    }

    std::cout << "\n\033[36mScan complete ✔️\033[0m\n";
}

void run_scanner(const std::string &targetIp, int startPort, int endPort, int timeoutMs) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }
#endif

    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
        std::cerr << "\033[35mInvalid port range! \n";
        return;
    }

    std::cout << "\033[36mAsync TCP connect scanner\033[0m\n";
    std::cout << "\033[36mTarget: " << targetIp
              << " Ports: " << startPort << "-" << endPort
              << " Timeout: " << timeoutMs << " ms\033[0m\n\n";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "failed for IP " << targetIp << "\n";
        return;
    }

    std::vector<Scanner> scans;
    scans.reserve(endPort - startPort + 1);

    for (int port = startPort; port <= endPort; ++port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            std::cerr << "failed for port " << port << "\n";
            continue;
        }

        // Set non-blocking
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sockfd, FIONBIO, &mode);
#else
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

        addr.sin_port = htons(static_cast<uint16_t>(port));
        int res = connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

#ifdef _WIN32
        int last_err = WSAGetLastError();
        if (res < 0 && last_err != WSAEWOULDBLOCK) {
#else
        if (res < 0 && errno != EINPROGRESS) {
#endif
            Scanner s{};
            s.sockfd = sockfd;
            s.port = port;
            s.completed = true;
#ifdef _WIN32
            if (last_err == WSAECONNREFUSED)
#else
            if (errno == ECONNREFUSED)
#endif
                s.state = PortState::CLOSED;
            else
                s.state = PortState::ERROR_STATE;
            s.msg = "failed immediately";
            close(sockfd);
            scans.push_back(s);
            continue;
        }

        Scanner s{};
        s.sockfd = sockfd;
        s.port = port;
        s.completed = false;
        s.state = PortState::ERROR_STATE;
        scans.push_back(s);
    }

    int remaining = 0;
    for (const auto &s : scans)
        if (!s.completed) remaining++;

    while (remaining > 0) {
        fd_set write_fds, err_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&err_fds);
        int max_fd = 0;

        for (const auto &s : scans) {
            if (!s.completed) {
                FD_SET(s.sockfd, &write_fds);
                FD_SET(s.sockfd, &err_fds);
                if (s.sockfd > max_fd) max_fd = s.sockfd;
            }
        }

        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int n = select(max_fd + 1, NULL, &write_fds, &err_fds, &tv);
        if (n < 0) {
            break;
        }
        if (n == 0) {
            for (auto &s : scans) {
                if (!s.completed) {
                    s.completed = true;
                    s.state = PortState::FILTERED;
                    s.msg = "timeout";
                    close(s.sockfd);
                    remaining--;
                }
            }
            break;
        }

        for (auto &s : scans) {
            if (!s.completed && (FD_ISSET(s.sockfd, &write_fds) || FD_ISSET(s.sockfd, &err_fds))) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(s.sockfd, SOL_SOCKET, SO_ERROR, (char*)&err, &len) < 0) {
                    s.state = PortState::ERROR_STATE;
                } else if (err == 0) {
                    s.state = PortState::OPEN;
                    s.msg = "open";
                } else {
                    s.state = PortState::CLOSED;
                    s.msg = "closed/refused";
                }
                s.completed = true;
                close(s.sockfd);
                remaining--;
            }
        }
    }

#ifdef _WIN32
    WSACleanup();
#endif
    print_scan_results(scans, startPort, endPort);
}
