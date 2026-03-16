package com.analyzer.dpi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages blocking/filtering rules for IPs, Apps, Domains, and Ports.
 * Merged from rule_manager.h and rule_manager.cpp
 */
public class RuleManager {

    // ============================================================================
    // Data Structures
    // ============================================================================
    
    public enum BlockType {
        IP, APP, DOMAIN, PORT
    }

    public static class BlockReason {
        public final BlockType type;
        public final String detail;

        public BlockReason(BlockType type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }

    // ============================================================================
    // Instance Variables (Thread-Safe)
    // ============================================================================
    
    private final Set<Long> blockedIps = ConcurrentHashMap.newKeySet();
    // Switched to Types.AppType
    private final Set<Types.AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final List<String> domainPatterns = new CopyOnWriteArrayList<>();
    private final Set<Integer> blockedPorts = ConcurrentHashMap.newKeySet();

    // ============================================================================
    // IP Blocking
    // ============================================================================

    public static long parseIP(String ip) {
        long result = 0;
        long octet = 0;
        int shift = 0;

        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }

    public static String ipToString(long ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public void blockIP(long ip) {
        blockedIps.add(ip);
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIP(String ip) {
        blockIP(parseIP(ip));
    }

    public void unblockIP(long ip) {
        blockedIps.remove(ip);
        System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
    }

    public void unblockIP(String ip) {
        unblockIP(parseIP(ip));
    }

    public boolean isIPBlocked(long ip) {
        return blockedIps.contains(ip);
    }

    public List<String> getBlockedIPs() {
        List<String> result = new ArrayList<>();
        for (long ip : blockedIps) {
            result.add(ipToString(ip));
        }
        return result;
    }

    // ============================================================================
    // Application Blocking
    // ============================================================================

    // Switched to Types.AppType
    public void blockApp(Types.AppType app) {
        blockedApps.add(app);
        System.out.println("[RuleManager] Blocked app: " + app.name());
    }

    public void unblockApp(Types.AppType app) {
        blockedApps.remove(app);
        System.out.println("[RuleManager] Unblocked app: " + app.name());
    }

    public boolean isAppBlocked(Types.AppType app) {
        return blockedApps.contains(app);
    }

    public List<Types.AppType> getBlockedApps() {
        return new ArrayList<>(blockedApps);
    }

    // ============================================================================
    // Domain Blocking
    // ============================================================================

    public void blockDomain(String domain) {
        if (domain.contains("*")) {
            domainPatterns.add(domain);
        } else {
            blockedDomains.add(domain);
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        if (domain.contains("*")) {
            domainPatterns.remove(domain);
        } else {
            blockedDomains.remove(domain);
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // e.g., ".example.com"
            
            if (domain.endsWith(suffix)) {
                return true;
            }
            // Also match the bare domain (example.com matches *.example.com)
            if (domain.equals(pattern.substring(2))) {
                return true;
            }
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        if (blockedDomains.contains(domain)) {
            return true;
        }

        String lowerDomain = domain.toLowerCase();
        for (String pattern : domainPatterns) {
            if (domainMatchesPattern(lowerDomain, pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public List<String> getBlockedDomains() {
        List<String> result = new ArrayList<>(blockedDomains);
        result.addAll(domainPatterns);
        return result;
    }

    // ============================================================================
    // Port Blocking
    // ============================================================================

    public void blockPort(int port) {
        blockedPorts.add(port);
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        blockedPorts.remove(port);
    }

    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port);
    }

    // ============================================================================
    // Combined Check
    // ============================================================================

    // Switched to Types.AppType
    public BlockReason shouldBlock(long srcIp, int dstPort, Types.AppType app, String domain) {
        if (isIPBlocked(srcIp)) {
            return new BlockReason(BlockType.IP, ipToString(srcIp));
        }
        if (isPortBlocked(dstPort)) {
            return new BlockReason(BlockType.PORT, String.valueOf(dstPort));
        }
        if (isAppBlocked(app)) {
            return new BlockReason(BlockType.APP, app.name());
        }
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(BlockType.DOMAIN, domain);
        }
        return null; // Return null if not blocked
    }

    // ============================================================================
    // Persistence
    // ============================================================================

    public boolean saveRules(String filename) {
        try {
            List<String> lines = new ArrayList<>();
            
            lines.add("[BLOCKED_IPS]");
            lines.addAll(getBlockedIPs());
            
            lines.add("\n[BLOCKED_APPS]");
            // Switched to Types.AppType
            for (Types.AppType app : getBlockedApps()) {
                lines.add(app.name());
            }
            
            lines.add("\n[BLOCKED_DOMAINS]");
            lines.addAll(getBlockedDomains());
            
            lines.add("\n[BLOCKED_PORTS]");
            for (int port : blockedPorts) {
                lines.add(String.valueOf(port));
            }

            Files.write(Paths.get(filename), lines);
            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));
            String currentSection = "";

            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.startsWith("[")) {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;
                    case "[BLOCKED_APPS]":
                        // Replaced the C++ loop hack with native Java Enum parsing
                        try {
                            blockApp(Types.AppType.valueOf(line));
                        } catch (IllegalArgumentException ex) {
                            System.err.println("Unknown AppType in rules file: " + line);
                        }
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        blockPort(Integer.parseInt(line));
                        break;
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException | NumberFormatException e) {
            System.err.println("Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        domainPatterns.clear();
        blockedPorts.clear();
        System.out.println("[RuleManager] All rules cleared");
    }

    // ============================================================================
    // Statistics
    // ============================================================================

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        stats.blockedIps = blockedIps.size();
        stats.blockedApps = blockedApps.size();
        stats.blockedDomains = blockedDomains.size() + domainPatterns.size();
        stats.blockedPorts = blockedPorts.size();
        return stats;
    }
}