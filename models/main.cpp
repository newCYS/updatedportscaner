#include "scanner.hpp"
#include "detector.hpp"
#include "honeypot.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <set>

static void print_usage(const char *progName) {
    std::cout
        << "Usage:\n"
        << "  " << progName << " --scan <ip> -p <start>-<end> [--timeout <ms>]\n"
        << "  " << progName << " --detect [--log <path>] [--threshold <n>]\n"
        << "  " << progName << " --honeypot -p <port> [--banner <message>] [--suspicious <ip1,ip2,...>]\n\n"
        << "Examples:\n"
        << "  " << progName << " --scan 127.0.0.1 -p 1-1000\n"
        << "  " << progName << " --detect\n"
        << "  " << progName << " --honeypot -p 22 --banner \"SSH-2.0-OpenSSH_8.2p1\"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "--scan") {
        if (argc < 5) {
            std::cerr << "[!] Not enough arguments for scan mode.\n\n";
            print_usage(argv[0]);
            return 1;
        }
        std::string targetIp = argv[2];
        if (std::string(argv[3]) != "-p") {
            std::cerr << "[!] Expected -p <start>-<end> for port range.\n\n";
            print_usage(argv[0]);
            return 1;
        }
        std::string range = argv[4];
        int dashPos = static_cast<int>(range.find('-'));
        if (dashPos == -1) {
            std::cerr << "[!] Port range must be in the form start-end (e.g. 1-1000).\n";
            return 1;
        }
        int startPort = std::atoi(range.substr(0, dashPos).c_str());
        int endPort   = std::atoi(range.substr(dashPos + 1).c_str());
        int timeoutMs = 3000;
        if (argc >= 7 && std::string(argv[5]) == "--timeout") {
            timeoutMs = std::atoi(argv[6]);
        }
        run_scanner(targetIp, startPort, endPort, timeoutMs);
        return 0;
    }

    if (mode == "--detect") {
        std::string logPath = "/var/log/syslog";
        int threshold = 5;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--log" && i + 1 < argc) {
                logPath = argv[++i];
            } else if (arg == "--threshold" && i + 1 < argc) {
                threshold = std::atoi(argv[++i]);
            }
        }
        
        std::set<std::string> blacklisted = run_detector(logPath, threshold);
        
        if (blacklisted.empty()) {
            std::cout << "[+] No suspicious activity detected.\n";
        } else {
            std::cout << "[!] Suspicious IPs detected (threshold > " << threshold << "):\n";
            for (const auto& ip : blacklisted) {
                std::cout << "  - " << ip << "\n";
            }
        }
        return 0;
    }

    if (mode == "--honeypot") {
        if (argc < 4 || std::string(argv[2]) != "-p") {
            std::cerr << "[!] Expected -p <port> for honeypot mode.\n\n";
            print_usage(argv[0]);
            return 1;
        }

        int port = std::atoi(argv[3]);
        std::string banner = "";
        std::set<std::string> suspicious_ips;

        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--banner" && i + 1 < argc) {
                banner = argv[++i];
            } else if (arg == "--suspicious" && i + 1 < argc) {
                std::string ips = argv[++i];
                size_t start = 0, end;
                while ((end = ips.find(',', start)) != std::string::npos) {
                    suspicious_ips.insert(ips.substr(start, end - start));
                    start = end + 1;
                }
                suspicious_ips.insert(ips.substr(start));
            }
        }

        run_honeypot(port, banner, suspicious_ips);
        return 0;
    }

    std::cerr << "[!] Unknown mode: " << mode << "\n\n";
    print_usage(argv[0]);
    return 1;
}
