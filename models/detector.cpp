#include "detector.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>

std::set<std::string> run_detector(const std::string& logPath, int suspicious_threshold) {
    std::set<std::string> blacklisted_ips;
    std::map<std::string, int> ip_counts;
    std::ifstream logFile(logPath);
    std::string line, ip;

    while (std::getline(logFile, line)) {
        std::stringstream ss(line);
        ss >> ip;
        if (!ip.empty()) {
            ip_counts[ip]++;
        }
    }

    for (auto const& [ip_addr, count] : ip_counts) {
        if (count > suspicious_threshold) {
            blacklisted_ips.insert(ip_addr);
        }
    }

    return blacklisted_ips;
}
