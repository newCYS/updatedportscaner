#ifndef DETECTOR_HPP
#define DETECTOR_HPP

#include <string>
#include <set>

std::set<std::string> run_detector(const std::string& logPath, int suspicious_threshold);

#endif // DETECTOR_HPP
