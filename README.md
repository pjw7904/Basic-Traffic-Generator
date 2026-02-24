# Basic Traffic Generator

A lightweight traffic generation and analysis tool designed for network protocol reconvergence experiments, particularly in testbed environments.

This tool provides post-capture analysis to measure:

- Packets received  
- Packets received out of order  
- Missing packets  
- Duplicate packets  

It is intentionally simple and suitable for automation inside experimental frameworks.

---

## Frame Structure

Each transmitted frame contains:

    [Ethernet II / IPv4 / ICMP / Custom Test Protocol Header]

The custom payload header format:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Source Physical Address                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Sequence Number                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Padding                                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Padding defaults to creating 1400 byte frames.

---


## Installation

On a typical Rocky Linux node:

    sudo dnf install -y python3 python3-pip wireshark
    sudo python3 -m pip install scapy

Clone the repository:

    git clone https://github.com/pjw7904/Basic-Traffic-Generator.git
    cd Basic-Traffic-Generator

---

## Usage

### Show Help

    python3 TrafficGenerator.py -h

---

# Sending Traffic

Send ICMP-based test traffic:

    sudo python3 TrafficGenerator.py -s <destination_ip> -c <count> -d <delay>

Example:

Send 100 packets to 10.0.0.2:

    sudo python3 TrafficGenerator.py -s 10.0.0.2 -c 100

Send continuously with delay:

    sudo python3 TrafficGenerator.py -s 10.0.0.2 -d 0.01

---

# Receiving Traffic

## Default Capture File (Recommended)

If -r is used without a filename, capture defaults to:

    results.pcap

Example:

    sudo python3 TrafficGenerator.py -r

This creates (if needed):

    ./results.pcap

The file is automatically:

- Created if it does not exist  
- Set to 777 permissions  
- Ownership restored to the invoking sudo user (when applicable)  

---

## Specify a Capture File

    sudo python3 TrafficGenerator.py -r test.pcap

Or with a full path:

    sudo python3 TrafficGenerator.py -r /home/rocky/test.pcap

---

# Analyzing Traffic

After capture:

    python3 TrafficGenerator.py -a <name>.pcap

This produces:

    <name>_result.txt

In the same directory as the pcap file.

Example output:

    3 frames lost from source 02:aa:bb:cc:dd:ee [4, 7, 9] | 100 received | 2 Not sequential [8, 15] | 1 duplicates [12]

---

# Default Interface

By default the script uses:

    eth1

Override with:

    -e <interface>

Example:

    sudo python3 TrafficGenerator.py -r -e eth2

---

# Typical Experimental Workflow (FABRIC)

On receiver node:

    sudo python3 TrafficGenerator.py -r

On sender node:

    sudo python3 TrafficGenerator.py -s <receiver_ip> -c 1000

After test:

    python3 TrafficGenerator.py -a results.pcap