#ifndef HONEYPOT_HPP
#define HONEYPOT_HPP

#include <string>
#include <set>

/**
 * @brief Runs a simple TCP honeypot on the specified port.
 * 
 * @param port The TCP port to listen on.
 * @param default_banner The message to send to normal clients.
 * @param suspicious_ips A set of IPs that should receive a different banner.
 */
void run_honeypot(int port, const std::string& default_banner, const std::set<std::string>& suspicious_ips);

#endif // HONEYPOT_HPP
