# Basic-Traffic-Generator

A basic traffic generator to determine:
    1. packets received.
    2. packets received out of order.
    3. packets missing.
    4. packets that are duplicates.

A custom test protocol header is placed in the payload of ICMP packets, resulting in frames containing:
    [Ethernet II / IPv4 / ICMP / test protocol]
