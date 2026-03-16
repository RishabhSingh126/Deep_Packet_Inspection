package com.analyzer.dpi;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Core Types for DPI Engine
 * Merged from types.h and types.cpp
 */
public class Types {

    // ============================================================================
    // Application Classification
    // ============================================================================
    public enum AppType {
        UNKNOWN("Unknown"),
        HTTP("HTTP"),
        HTTPS("HTTPS"),
        DNS("DNS"),
        TLS("TLS"),
        QUIC("QUIC"),
        GOOGLE("Google"),
        FACEBOOK("Facebook"),
        YOUTUBE("YouTube"),
        TWITTER("Twitter/X"),
        INSTAGRAM("Instagram"),
        NETFLIX("Netflix"),
        AMAZON("Amazon"),
        MICROSOFT("Microsoft"),
        APPLE("Apple"),
        WHATSAPP("WhatsApp"),
        TELEGRAM("Telegram"),
        TIKTOK("TikTok"),
        SPOTIFY("Spotify"),
        ZOOM("Zoom"),
        DISCORD("Discord"),
        GITHUB("GitHub"),
        CLOUDFLARE("Cloudflare");

        private final String label;

        AppType(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    // ============================================================================
    // Connection State
    // ============================================================================
    public enum ConnectionState {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    // ============================================================================
    // Packet Action (what to do with the packet)
    // ============================================================================
    public enum PacketAction {
        FORWARD,    // Send to internet
        DROP,       // Block/drop the packet
        INSPECT,    // Needs further inspection
        LOG_ONLY    // Forward but log
    }

    // ============================================================================
    // Five-Tuple: Uniquely identifies a connection/flow
    // ============================================================================
    public static class FiveTuple {
        public long srcIp;      // uint32_t equivalent
        public long dstIp;      // uint32_t equivalent
        public int srcPort;     // uint16_t equivalent
        public int dstPort;     // uint16_t equivalent
        public int protocol;    // uint8_t equivalent (TCP=6, UDP=17)

        public FiveTuple() {}

        public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FiveTuple fiveTuple = (FiveTuple) o;
            return srcIp == fiveTuple.srcIp &&
                   dstIp == fiveTuple.dstIp &&
                   srcPort == fiveTuple.srcPort &&
                   dstPort == fiveTuple.dstPort &&
                   protocol == fiveTuple.protocol;
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
        }

        private String formatIp(long ip) {
            return ((ip) & 0xFF) + "." +
                   ((ip >> 8) & 0xFF) + "." +
                   ((ip >> 16) & 0xFF) + "." +
                   ((ip >> 24) & 0xFF);
        }

        @Override
        public String toString() {
            String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
            return formatIp(srcIp) + ":" + srcPort + " -> " + formatIp(dstIp) + ":" + dstPort + " (" + protoStr + ")";
        }
    }

    // ============================================================================
    // Connection Entry (tracked per flow)
    // ============================================================================
    public static class Connection {
        public FiveTuple tuple;
        public ConnectionState state = ConnectionState.NEW;
        public AppType appType = AppType.UNKNOWN;
        public String sni = ""; 
        
        public long packetsIn = 0;
        public long packetsOut = 0;
        public long bytesIn = 0;
        public long bytesOut = 0;
        
        public long firstSeen; // Unix timestamp in ms
        public long lastSeen;  // Unix timestamp in ms
        
        public PacketAction action = PacketAction.FORWARD;
        
        // For TCP state tracking
        public boolean synSeen = false;
        public boolean synAckSeen = false;
        public boolean finSeen = false;
    }

    // ============================================================================
    // Packet wrapper for queue passing
    // ============================================================================
    public static class PacketJob {
        public long packetId;
        public FiveTuple tuple;
        public byte[] data;
        
        public int ethOffset = 0;
        public int ipOffset = 0;
        public int transportOffset = 0;
        public int payloadOffset = 0;
        public int payloadLength = 0;
        public int tcpFlags = 0;
        
        // Timestamps
        public long tsSec;
        public long tsUsec;
    }

    // ============================================================================
    // Statistics - uses AtomicLong for thread safety
    // ============================================================================
    public static class DPIStats {
        public final AtomicLong totalPackets = new AtomicLong(0);
        public final AtomicLong totalBytes = new AtomicLong(0);
        public final AtomicLong forwardedPackets = new AtomicLong(0);
        public final AtomicLong droppedPackets = new AtomicLong(0);
        public final AtomicLong tcpPackets = new AtomicLong(0);
        public final AtomicLong udpPackets = new AtomicLong(0);
        public final AtomicLong otherPackets = new AtomicLong(0);
        public final AtomicLong activeConnections = new AtomicLong(0);
    }

    // ============================================================================
    // SNI to Application Mapper
    // ============================================================================
    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return AppType.UNKNOWN;
        }
        
        String lowerSni = sni.toLowerCase();
        
        // Google (including YouTube, which is owned by Google)
        if (lowerSni.contains("google") || lowerSni.contains("gstatic") ||
            lowerSni.contains("googleapis") || lowerSni.contains("ggpht") ||
            lowerSni.contains("gvt1")) {
            return AppType.GOOGLE;
        }
        
        // YouTube
        if (lowerSni.contains("youtube") || lowerSni.contains("ytimg") ||
            lowerSni.contains("youtu.be") || lowerSni.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }
        
        // Facebook/Meta
        if (lowerSni.contains("facebook") || lowerSni.contains("fbcdn") ||
            lowerSni.contains("fb.com") || lowerSni.contains("fbsbx") ||
            lowerSni.contains("meta.com")) {
            return AppType.FACEBOOK;
        }
        
        // Instagram (owned by Meta)
        if (lowerSni.contains("instagram") || lowerSni.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        
        // WhatsApp (owned by Meta)
        if (lowerSni.contains("whatsapp") || lowerSni.contains("wa.me")) {
            return AppType.WHATSAPP;
        }
        
        // Twitter/X
        if (lowerSni.contains("twitter") || lowerSni.contains("twimg") ||
            lowerSni.contains("x.com") || lowerSni.contains("t.co")) {
            return AppType.TWITTER;
        }
        
        // Netflix
        if (lowerSni.contains("netflix") || lowerSni.contains("nflxvideo") ||
            lowerSni.contains("nflximg")) {
            return AppType.NETFLIX;
        }
        
        // Amazon
        if (lowerSni.contains("amazon") || lowerSni.contains("amazonaws") ||
            lowerSni.contains("cloudfront") || lowerSni.contains("aws")) {
            return AppType.AMAZON;
        }
        
        // Microsoft
        if (lowerSni.contains("microsoft") || lowerSni.contains("msn.com") ||
            lowerSni.contains("office") || lowerSni.contains("azure") ||
            lowerSni.contains("live.com") || lowerSni.contains("outlook") ||
            lowerSni.contains("bing")) {
            return AppType.MICROSOFT;
        }
        
        // Apple
        if (lowerSni.contains("apple") || lowerSni.contains("icloud") ||
            lowerSni.contains("mzstatic") || lowerSni.contains("itunes")) {
            return AppType.APPLE;
        }
        
        // Telegram
        if (lowerSni.contains("telegram") || lowerSni.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        
        // TikTok
        if (lowerSni.contains("tiktok") || lowerSni.contains("tiktokcdn") ||
            lowerSni.contains("musical.ly") || lowerSni.contains("bytedance")) {
            return AppType.TIKTOK;
        }
        
        // Spotify
        if (lowerSni.contains("spotify") || lowerSni.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }
        
        // Zoom
        if (lowerSni.contains("zoom")) {
            return AppType.ZOOM;
        }
        
        // Discord
        if (lowerSni.contains("discord") || lowerSni.contains("discordapp")) {
            return AppType.DISCORD;
        }
        
        // GitHub
        if (lowerSni.contains("github") || lowerSni.contains("githubusercontent")) {
            return AppType.GITHUB;
        }
        
        // Cloudflare
        if (lowerSni.contains("cloudflare") || lowerSni.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }
        
        // If SNI is present but not recognized, still mark as TLS/HTTPS
        return AppType.HTTPS;
    }
}