# mdnsproxy

A simple DNS resolver server which can answer unicast DNS queries for
both the global and mDNS namespaces. All queries will be proxied
either to a conventional unicast DNS server or to the mDNS multicast
server address 224.0.0.251.

In other words, you can start this server and then use it in your
/etc/resolv.conf file to resolve both internet hostnames and local
mDNS names.
