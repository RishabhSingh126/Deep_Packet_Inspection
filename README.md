# High-Performance Deep Packet Inspection (DPI) Engine

![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Maven](https://img.shields.io/badge/Maven-Build-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white)
![Networking](https://img.shields.io/badge/Networking-PCAP-0052CC?style=for-the-badge)

## Overview
This project is a custom-built, multithreaded **Deep Packet Inspection (DPI) Engine** developed entirely from scratch in Java. It operates as a high-performance network filter capable of analyzing raw `.pcap` network traffic, extracting Layer 7 (Application) payloads, classifying traffic (e.g., YouTube, Netflix, Twitter), and enforcing rule-based packet dropping in real-time.

Unlike standard firewalls that only check IP addresses and ports, this engine performs deep payload inspection using **Server Name Indication (SNI)** and **HTTP Host extraction** to accurately identify and block specific applications, even over encrypted TLS connections.

## Key Technical Features
* **Multithreaded Architecture:** Utilizes a custom Load Balancer to distribute incoming network packets across multiple Fast Path worker threads, preventing bottlenecks during heavy traffic analysis.
* **Layer 7 Application Classification:** Parses raw byte streams to identify protocols (TCP/UDP) and extracts domain names to classify traffic into distinct app categories.
* **Stateful Connection Tracking:** Maintains active connection states in memory. Once a flow is classified and blocked, subsequent packets in the same flow are dropped instantly without redundant payload inspection (O(1) lookup).
* **Robust Rule Engine:** Supports dynamic blocking based on exact IP addresses, specific Applications (e.g., `YouTube`, `TikTok`), or wildcard Domain matchers.

## System Architecture

The engine is designed using a scalable worker-pool model:

```text
 ┌───────────────┐
 │  PCAP Reader  │ Reads raw packets from input file
 └───────┬───────┘
         │ hash(5-tuple) % num_lbs
         ▼
 ┌───────┴───────┐
 │ Load Balancer │ Distributes packets evenly
 │   LB0 │ LB1   │
 └─┬─────┴─────┬─┘
   │           │   hash(5-tuple) % fps_per_lb
   ▼           ▼
 ┌─┴───┐   ┌───┴─┐
 │FP0-1│   │FP2-3│ Fast Path Threads: DPI, Classification, Rule Matching
 └─┬───┘   └───┬─┘
   │           │
   ▼           ▼
 ┌─┴───────────┴─┐
 │ Output Writer │ Forwards safe packets, silently drops blocked packets
 └───────────────┘

 ## Tech Stack
* **Language:** Java (JDK 17+)
* **Libraries:** `Pcap4J` (Java wrapper for `libpcap`/`Npcap`)
* **Build System:** Apache Maven
* **Testing & Validation:** Wireshark, `tshark`, raw `.pcap` analysis