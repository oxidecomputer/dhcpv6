# Dhcpv6

This is a library that supports the decoding and encoding of DHCPv6 messages.

This library currently supports the initial DHCPv6 RFC (rfc3315) and the DNS configuration options (rfc3646).

### Todo:
- Add support for Relay messages
- Add support for the Authentication Option
- Improve encode performance.  We can eliminate the copies by building the packet in place, and backfilling the field lengths.
- Add test cases covering the remaining option types
