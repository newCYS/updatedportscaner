#include "honeypot.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <set>
#include <vector>
#include <signal.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
    typedef int socklen_t;
    #ifndef _SSIZE_T_DEFINED
        #define _SSIZE_T_DEFINED
        #undef ssize_t
        #ifdef _WIN64
            typedef __int64 ssize_t;
        #else
            typedef int ssize_t;
        #endif
    #endif
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
#endif

#define MAX_PENDING_CONNECTIONS 10

// Global flag for graceful shutdown
volatile sig_atomic_t stop_honeypot = 0;

#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        stop_honeypot = 1;
        return TRUE;
    }
    return FALSE;
}
#else
void handle_sigint(int sig) {
    (void)sig;
    stop_honeypot = 1;
}
#endif

void run_honeypot(int port, const std::string& default_banner, const std::set<std::string>& suspicious_ips) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, handle_sigint);
#endif

    int listen_fd, conn_fd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    std::cout << "[*] Starting honeypot on port " << port << "...\n";
    std::cout << "[*] Press Ctrl+C to stop the honeypot.\n";

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

    int enable_reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable_reuse, sizeof(enable_reuse));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(static_cast<u_short>(port));

    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed");
        std::cerr << "[!] Tip: Port " << port << " might be in use or requires root privileges (sudo).\n";
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen failed");
        close(listen_fd);
        return;
    }

    // Set non-blocking for the listen socket so we can check the stop flag
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(listen_fd, FIONBIO, &mode);
#else
    int flags = fcntl(listen_fd, F_GETFL, 0);
    fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);
#endif

    std::cout << "[*] Honeypot listening for connections...\n";

    while (!stop_honeypot) {
        conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (conn_fd < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                Sleep(100);
                continue;
            }
#else
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                usleep(100000);
                continue;
            }
#endif
            if (stop_honeypot) break;
            perror("accept failed");
            continue;
        }

        std::string client_ip = inet_ntoa(cli_addr.sin_addr);
        time_t now = time(0);
        char* dt = ctime(&now);
        if (dt[strlen(dt) - 1] == '\n') dt[strlen(dt) - 1] = '\0';

        // Log to file
        std::ofstream logFile("service_logs.txt", std::ios::app);
        if (logFile.is_open()) {
            logFile << client_ip << " " << now << " [" << dt << "]" << std::endl;
            logFile.close();
        }

        std::cout << "--------------------------------------------------\n";
        std::cout << "[!] Connection from: " << client_ip << " at " << dt << "\n";
        
        std::string banner_to_send = default_banner;
        if (suspicious_ips.find(client_ip) != suspicious_ips.end()) {
            banner_to_send = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2";
            std::cout << "[*] Suspicious IP detected! Sending fake SSH banner.\n";
        }

        if (!banner_to_send.empty()) {
            std::string full_banner = banner_to_send + "\r\n";
            send(conn_fd, full_banner.c_str(), static_cast<int>(full_banner.length()), 0);
        }

        close(conn_fd);
        std::cout << "[*] Connection closed.\n";
    }

    std::cout << "\n[*] Stopping honeypot...\n";
    close(listen_fd);
#ifdef _WIN32
    WSACleanup();
#endif
}
