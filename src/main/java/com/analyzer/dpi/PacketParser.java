package com.analyzer.dpi;

/**
 * Parses raw network packets into human-readable and structured formats.
 * Merged from packet_parser.h and packet_parser.cpp
 */
public class PacketParser {

    // ============================================================================
    // Constants
    // ============================================================================
    public static final class TCPFlags {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;
    }

    public static final class Protocol {
        public static final int ICMP = 1;
        public static final int TCP = 6;
        public static final int UDP = 17;
    }

    public static final class EtherType {
        public static final int IPv4 = 0x0800;
        public static final int IPv6 = 0x86DD;
        public static final int ARP = 0x0806;
    }

    // ============================================================================
    // Parsed Packet Data Structure
    // ============================================================================
    public static class ParsedPacket {
        // Timestamps
        public long timestampSec;
        public long timestampUsec;
        
        // Ethernet layer
        public String srcMac;
        public String destMac;
        public int etherType;
        
        // IP layer (if present)
        public boolean hasIp = false;
        public int ipVersion;
        public String srcIp;
        public String destIp;
        
        // Added raw IP numbers to support Types.FiveTuple and RuleManager alignment
        public long srcIpRaw;  
        public long destIpRaw; 
        
        public int protocol;          // TCP=6, UDP=17, ICMP=1
        public int ttl;
        
        // Transport layer (if present)
        public boolean hasTcp = false;
        public boolean hasUdp = false;
        public int srcPort;
        public int destPort;
        
        // TCP-specific
        public int tcpFlags;
        public long seqNumber;
        public long ackNumber;
        
        // Payload (Replaces C++ pointer with array reference and offset)
        public int payloadLength;
        public int payloadOffset;
        public byte[] rawData; 
    }

    // ============================================================================
    // Main Parsing Logic
    // ============================================================================
    
    /**
     * Parses a raw packet. 
     * Note: PcapReader.RawPacket will be fully resolved when we create PcapReader.java in Step 4.
     */
    public static ParsedPacket parse(PcapReader.RawPacket raw) {
        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        
        byte[] data = raw.data;
        int len = data.length;
        parsed.rawData = data;
        
        int offset = 0;
        
        // Parse Ethernet header first
        offset = parseEthernet(data, len, parsed, offset);
        if (offset < 0) return null; // Packet parsing failed
        
        // Parse IP layer if it's an IPv4 packet
        if (parsed.etherType == EtherType.IPv4) {
            offset = parseIPv4(data, len, parsed, offset);
            
            if (offset >= 0) {
                // Parse transport layer based on protocol
                if (parsed.protocol == Protocol.TCP) {
                    offset = parseTCP(data, len, parsed, offset);
                } else if (parsed.protocol == Protocol.UDP) {
                    offset = parseUDP(data, len, parsed, offset);
                }
            } else {
                return null;
            }
        }
        
        // Set payload information
        if (offset >= 0 && offset < len) {
            parsed.payloadLength = len - offset;
            parsed.payloadOffset = offset;
        } else {
            parsed.payloadLength = 0;
            parsed.payloadOffset = -1;
        }
        
        return parsed;
    }

    // ============================================================================
    // Private Layer Parsers (returns new offset, or -1 if packet is too short)
    // ============================================================================

    private static int parseEthernet(byte[] data, int len, ParsedPacket parsed, int offset) {
        if (len < offset + 14) return -1; // Packet too short
        
        parsed.destMac = macToString(data, offset);
        parsed.srcMac = macToString(data, offset + 6);
        
        // Read 16-bit EtherType
        parsed.etherType = ((data[offset + 12] & 0xFF) << 8) | (data[offset + 13] & 0xFF);
        
        return offset + 14;
    }

    private static int parseIPv4(byte[] data, int len, ParsedPacket parsed, int offset) {
        if (len < offset + 20) return -1; // Min IPv4 header is 20 bytes
        
        int versionIhl = data[offset] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        
        if (parsed.ipVersion != 4) return -1; // Not IPv4
        
        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || len < offset + ipHeaderLen) return -1;
        
        parsed.ttl = data[offset + 8] & 0xFF;
        parsed.protocol = data[offset + 9] & 0xFF;
        
        parsed.srcIp = ipToString(data, offset + 12);
        parsed.destIp = ipToString(data, offset + 16);
        
        // Extract raw uint32_t IPs in Little-Endian format to match RuleManager.parseIP() logic
        parsed.srcIpRaw = ((long)(data[offset + 12] & 0xFF)) |
                          (((long) data[offset + 13] & 0xFF) << 8) |
                          (((long) data[offset + 14] & 0xFF) << 16) |
                          (((long) data[offset + 15] & 0xFF) << 24);

        parsed.destIpRaw = ((long)(data[offset + 16] & 0xFF)) |
                           (((long) data[offset + 17] & 0xFF) << 8) |
                           (((long) data[offset + 18] & 0xFF) << 16) |
                           (((long) data[offset + 19] & 0xFF) << 24);
        
        parsed.hasIp = true;
        return offset + ipHeaderLen;
    }

    private static int parseTCP(byte[] data, int len, ParsedPacket parsed, int offset) {
        if (len < offset + 20) return -1; // Min TCP header is 20 bytes
        
        parsed.srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        parsed.destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        
        parsed.seqNumber = (((long) data[offset + 4] & 0xFF) << 24) |
                           (((long) data[offset + 5] & 0xFF) << 16) |
                           (((long) data[offset + 6] & 0xFF) << 8) |
                           ((long) data[offset + 7] & 0xFF);
                           
        parsed.ackNumber = (((long) data[offset + 8] & 0xFF) << 24) |
                           (((long) data[offset + 9] & 0xFF) << 16) |
                           (((long) data[offset + 10] & 0xFF) << 8) |
                           ((long) data[offset + 11] & 0xFF);
                           
        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        
        parsed.tcpFlags = data[offset + 13] & 0xFF;
        
        if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) return -1;
        
        parsed.hasTcp = true;
        return offset + tcpHeaderLen;
    }

    private static int parseUDP(byte[] data, int len, ParsedPacket parsed, int offset) {
        if (len < offset + 8) return -1; // UDP header is always 8 bytes
        
        parsed.srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        parsed.destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        
        parsed.hasUdp = true;
        return offset + 8;
    }

    // ============================================================================
    // Helper Formatters
    // ============================================================================

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Protocol.ICMP: return "ICMP";
            case Protocol.TCP:  return "TCP";
            case Protocol.UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) result.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) result.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) result.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) result.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) result.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) result.append("URG ");
        
        String res = result.toString().trim();
        return res.isEmpty() ? "none" : res;
    }
}