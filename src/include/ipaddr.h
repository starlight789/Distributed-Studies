#ifndef CEPH_IPADDR_H
#define CEPH_IPADDR_H

#include <arpa/inet.h>

/*
 * Find an IP address that is in the wanted subnet.
 *
 * If there are multiple matches, the first one is returned; this order
 * is system-dependent and should not be relied on.
 */
const struct ifaddrs *find_ip_in_subnet(const struct ifaddrs *addrs,
					 const struct sockaddr *net,
					 unsigned int prefix_len);

/*
 * Validate and parse IPv4 or IPv6 network
 *
 * Given a network (e.g. "192.168.0.0/24") and pointers to a sockaddr_storage
 * struct and an unsigned int:
 *
 * if the network string is valid, return true and populate sockaddr_storage
 * and prefix_len;
 *
 * if the network string is invalid, return false.
 */
bool parse_network(const char *s, struct sockaddr_storage *network, unsigned int *prefix_len);

inline void netmask_ipv4(const struct in_addr *addr,
			 unsigned int prefix_len,
			 struct in_addr *out) {
  uint32_t mask;

  if (prefix_len >= 32) {
    // also handle 32 in this branch, because >>32 is not defined by
    // the C standards
    mask = ~uint32_t(0);
  } else {
    mask = htonl(~(~uint32_t(0) >> prefix_len));
  }
  out->s_addr = addr->s_addr & mask;
}

#endif
