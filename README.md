#  Deep Packet Inspection (DPI) Engine

A high-performance network packet analyzer built in **C++** using `libpcap`. This engine captures, decodes, and inspects raw network traffic across multiple OSI layers, providing detailed visibility into network payloads and detecting simulated malicious activities.



##  Project Overview
This project demonstrates low-level systems programming, memory management, and a deep understanding of computer networking. It ingests `.pcap` files, strips network packets down layer by layer, and analyzes the underlying application data.

###  Key Features:
* **Multi-Layer Protocol Parsing:** Decodes Ethernet, IPv4, TCP, and UDP headers from raw byte streams.
* **Application Layer Inspection:** Extracts and previews payloads for HTTP requests, DNS queries, and TLS/SSL (SNI) handshakes.
* **Threat Detection:** Implements rule-based anomaly detection to flag malicious traffic, such as SYN floods or unauthorized IP access.
* **Automated Traffic Generation:** Includes a custom Python (`scapy`) script to generate mock network traffic for rigorous engine testing.

##  Tech Stack
* **Language:** C++
* **Libraries:** `libpcap`
* **Build System:** CMake
* **Testing & Validation:** Python 3 (`scapy`), Wireshark
