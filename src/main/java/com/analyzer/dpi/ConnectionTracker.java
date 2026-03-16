package com.analyzer.dpi;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * Maintains flow tables for all active connections and aggregates global stats.
 * Merged from connection_tracker.h and connection_tracker.cpp
 */
public class ConnectionTracker {

    // ============================================================================
    // Tracker Statistics Structure
    // ============================================================================
    public static class TrackerStats {
        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }

    // ============================================================================
    // Instance Variables
    // ============================================================================
    private final int fpId;
    private final int maxConnections;
    
    // ConcurrentHashMap ensures thread safety when Global table reads while FP thread writes
    private final ConcurrentHashMap<Types.FiveTuple, Types.Connection> connections;
    
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    // ============================================================================
    // Constructor
    // ============================================================================
    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        this.connections = new ConcurrentHashMap<>();
    }

    // ============================================================================
    // Core Tracking Logic
    // ============================================================================

    public Types.Connection getOrCreateConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Check if we need to evict old connections
        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        // Create new connection
        Types.Connection newConn = new Types.Connection();
        newConn.tuple = tuple;
        newConn.state = Types.ConnectionState.NEW;
        newConn.firstSeen = System.currentTimeMillis();
        newConn.lastSeen = newConn.firstSeen;

        // Use putIfAbsent to prevent race conditions during creation
        Types.Connection existing = connections.putIfAbsent(tuple, newConn);
        if (existing != null) {
            return existing;
        }

        totalSeen++;
        return newConn;
    }

    public Types.Connection getConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Try reverse tuple (for bidirectional matching)
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Types.Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;

        conn.lastSeen = System.currentTimeMillis();

        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    // Switched 'int app' to 'Types.AppType app'
    public void classifyConnection(Types.Connection conn, Types.AppType app, String sni) {
        if (conn == null) return;

        if (conn.state != Types.ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = Types.ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Types.Connection conn) {
        if (conn == null) return;

        conn.state = Types.ConnectionState.BLOCKED;
        conn.action = Types.PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = Types.ConnectionState.CLOSED;
        }
    }

    public int cleanupStale(long timeoutSeconds) {
        long now = System.currentTimeMillis();
        long timeoutMillis = timeoutSeconds * 1000;
        int removed = 0;

        Iterator<Map.Entry<Types.FiveTuple, Types.Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<Types.FiveTuple, Types.Connection> entry = it.next();
            Types.Connection conn = entry.getValue();
            long age = now - conn.lastSeen;

            if (age > timeoutMillis || conn.state == Types.ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }

        return removed;
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;

        Types.FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;

        // O(N) scan to find the oldest. 
        for (Map.Entry<Types.FiveTuple, Types.Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen < oldestTime) {
                oldestTime = entry.getValue().lastSeen;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    // ============================================================================
    // Data Retrieval
    // ============================================================================

    public List<Types.Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    public void clear() {
        connections.clear();
    }

    public void forEach(Consumer<Types.Connection> callback) {
        for (Types.Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    // ============================================================================
    // Global Connection Table - Aggregates stats from all FP trackers
    // ============================================================================
    public static class GlobalConnectionTable {
        
        public static class GlobalStats {
            public long totalActiveConnections;
            public long totalConnectionsSeen;
            // Switched from Integer to Types.AppType
            public Map<Types.AppType, Long> appDistribution = new HashMap<>();
            public List<Map.Entry<String, Long>> topDomains = new ArrayList<>();
        }

        private final ConnectionTracker[] trackers;
        private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

        public GlobalConnectionTable(int numFps) {
            trackers = new ConnectionTracker[numFps];
        }

        public void registerTracker(int fpId, ConnectionTracker tracker) {
            lock.writeLock().lock();
            try {
                if (fpId >= 0 && fpId < trackers.length) {
                    trackers[fpId] = tracker;
                }
            } finally {
                lock.writeLock().unlock();
            }
        }

        public GlobalStats getGlobalStats() {
            lock.readLock().lock();
            try {
                GlobalStats stats = new GlobalStats();
                stats.totalActiveConnections = 0;
                stats.totalConnectionsSeen = 0;

                Map<String, Long> domainCounts = new HashMap<>();

                for (ConnectionTracker tracker : trackers) {
                    if (tracker == null) continue;

                    TrackerStats trackerStats = tracker.getStats();
                    stats.totalActiveConnections += trackerStats.activeConnections;
                    stats.totalConnectionsSeen += trackerStats.totalConnectionsSeen;

                    tracker.forEach(conn -> {
                        stats.appDistribution.put(conn.appType, 
                            stats.appDistribution.getOrDefault(conn.appType, 0L) + 1);
                        
                        if (conn.sni != null && !conn.sni.isEmpty()) {
                            domainCounts.put(conn.sni, 
                                domainCounts.getOrDefault(conn.sni, 0L) + 1);
                        }
                    });
                }

                // Sort domains by count descending
                List<Map.Entry<String, Long>> domainVec = new ArrayList<>(domainCounts.entrySet());
                domainVec.sort((a, b) -> b.getValue().compareTo(a.getValue()));

                // Take top 20
                int count = Math.min(domainVec.size(), 20);
                stats.topDomains = new ArrayList<>(domainVec.subList(0, count));

                return stats;
            } finally {
                lock.readLock().unlock();
            }
        }

        public String generateReport() {
            GlobalStats stats = getGlobalStats();
            StringBuilder ss = new StringBuilder();

            ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
            ss.append("║               CONNECTION STATISTICS REPORT                   ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            ss.append(String.format("║ Active Connections:     %-36d ║\n", stats.totalActiveConnections));
            ss.append(String.format("║ Total Connections Seen: %-36d ║\n", stats.totalConnectionsSeen));

            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                    APPLICATION BREAKDOWN                     ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            long total = stats.appDistribution.values().stream().mapToLong(Long::longValue).sum();

            // Switched to Types.AppType
            List<Map.Entry<Types.AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
            sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            for (Map.Entry<Types.AppType, Long> pair : sortedApps) {
                double pct = total > 0 ? (100.0 * pair.getValue() / total) : 0;
                // Used native Java Enum name() method
                String appName = pair.getKey().name(); 
                ss.append(String.format("║ %-20s %10d (%5.1f%%)           ║\n", appName, pair.getValue(), pct));
            }

            if (!stats.topDomains.isEmpty()) {
                ss.append("╠══════════════════════════════════════════════════════════════╣\n");
                ss.append("║                      TOP DOMAINS                             ║\n");
                ss.append("╠══════════════════════════════════════════════════════════════╣\n");

                for (Map.Entry<String, Long> pair : stats.topDomains) {
                    String domain = pair.getKey();
                    if (domain.length() > 35) {
                        domain = domain.substring(0, 32) + "...";
                    }
                    ss.append(String.format("║ %-40s %10d           ║\n", domain, pair.getValue()));
                }
            }

            ss.append("╚══════════════════════════════════════════════════════════════╝\n");

            return ss.toString();
        }
    }
}