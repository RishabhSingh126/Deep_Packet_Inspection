package com.analyzer.dpi;

import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor - Handles packet processing, connection tracking, and rule enforcement.
 * Merged from fast_path.h and fast_path.cpp
 */
public class FastPath {

    // ============================================================================
    // Interfaces & Data Structures
    // ============================================================================

    /** Callback for when a packet should be forwarded or dropped */
    public interface PacketOutputCallback extends BiConsumer<Types.PacketJob, Types.PacketAction> {}

    // ============================================================================
    // Fast Path Processor Thread
    // ============================================================================
    public static class FastPathProcessor implements Runnable {

        public static class FPStats {
            public long packetsProcessed;
            public long packetsForwarded;
            public long packetsDropped;
            public long connectionsTracked;
            public long sniExtractions;
            public long classificationHits;
        }

        private final int fpId;
        private final LinkedBlockingQueue<Types.PacketJob> inputQueue;
        private final ConnectionTracker connTracker;
        private final RuleManager ruleManager;
        private final PacketOutputCallback outputCallback;

        // Statistics
        private final AtomicLong packetsProcessed = new AtomicLong(0);
        private final AtomicLong packetsForwarded = new AtomicLong(0);
        private final AtomicLong packetsDropped = new AtomicLong(0);
        private final AtomicLong sniExtractions = new AtomicLong(0);
        private final AtomicLong classificationHits = new AtomicLong(0);

        // Thread control
        private final AtomicBoolean running = new AtomicBoolean(false);
        private Thread thread;

        public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
            this.fpId = fpId;
            this.inputQueue = new LinkedBlockingQueue<>(10000);
            this.connTracker = new ConnectionTracker(fpId, 100000);
            this.ruleManager = ruleManager;
            this.outputCallback = outputCallback;
        }

        public void start() {
            if (running.get()) return;
            running.set(true);
            thread = new Thread(this, "FP-Thread-" + fpId);
            thread.start();
            System.out.println("[FP" + fpId + "] Started");
        }

        public void stop() {
            if (!running.get()) return;
            running.set(false);
            if (thread != null) {
                thread.interrupt(); // Wake up if waiting on queue
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
        }

        public LinkedBlockingQueue<Types.PacketJob> getInputQueue() {
            return inputQueue;
        }

        public ConnectionTracker getConnectionTracker() {
            return connTracker;
        }

        public int getId() {
            return fpId;
        }

        public boolean isRunning() {
            return running.get();
        }

        @Override
        public void run() {
            while (running.get()) {
                try {
                    // Poll queue with 100ms timeout
                    Types.PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                    
                    if (job == null) {
                        // Periodically cleanup stale connections (timeout: 300 seconds)
                        connTracker.cleanupStale(300);
                        continue;
                    }

                    packetsProcessed.incrementAndGet();

                    // Process the packet
                    Types.PacketAction action = processPacket(job);

                    // Call output callback
                    if (outputCallback != null) {
                        outputCallback.accept(job, action);
                    }

                    // Update stats
                    if (action == Types.PacketAction.DROP) {
                        packetsDropped.incrementAndGet();
                    } else {
                        packetsForwarded.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    // Interrupted means we should shut down
                    if (!running.get()) break;
                } catch (Exception e) {
                    System.err.println("[FP" + fpId + "] Error processing packet: " + e.getMessage());
                }
            }
        }

        private Types.PacketAction processPacket(Types.PacketJob job) {
            Types.Connection conn = connTracker.getOrCreateConnection(job.tuple);
            if (conn == null) {
                return Types.PacketAction.FORWARD;
            }

            // Update connection stats
            boolean isOutbound = true; // In this model, all packets from user are outbound
            connTracker.updateConnection(conn, job.data.length, isOutbound);

            // Update TCP state if applicable
            if (job.tuple.protocol == 6) { // TCP
                updateTCPState(conn, (byte) job.tcpFlags);
            }

            // If connection is already blocked, drop immediately
            if (conn.state == Types.ConnectionState.BLOCKED) {
                return Types.PacketAction.DROP;
            }

            // If connection not yet classified, try to inspect payload
            if (conn.state != Types.ConnectionState.CLASSIFIED && job.payloadLength > 0) {
                inspectPayload(job, conn);
            }

            // Check rules (even for classified connections, as rules might change)
            return checkRules(job, conn);
        }

        private void inspectPayload(Types.PacketJob job, Types.Connection conn) {
            if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) {
                return;
            }

            // Try TLS SNI extraction first
            if (tryExtractSNI(job, conn)) return;

            // Try HTTP Host header extraction
            if (tryExtractHTTPHost(job, conn)) return;

            // Check for DNS (port 53)
            if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
                // Assuming DNSExtractor exists
                String domain = SniExtractor.DnsExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
                if (domain != null) {
                    connTracker.classifyConnection(conn, Types.AppType.DNS, domain);
                    return;
                }
            }

            // Basic port-based classification as fallback
            if (job.tuple.dstPort == 80) {
                connTracker.classifyConnection(conn, Types.AppType.HTTP, "");
            } else if (job.tuple.dstPort == 443) {
                connTracker.classifyConnection(conn, Types.AppType.HTTPS, "");
            }
        }

        private boolean tryExtractSNI(Types.PacketJob job, Types.Connection conn) {
            if (job.tuple.dstPort != 443 && job.payloadLength < 50) {
                return false;
            }
            if (job.payloadOffset >= job.data.length || job.payloadLength == 0) {
                return false;
            }

            // Assuming SNIExtractor exists
            String sni = SniExtractor.TlsSniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
            if (sni != null) {
                sniExtractions.incrementAndGet();
                
                // Using AppType Enum
                Types.AppType app = Types.sniToAppType(sni);
                connTracker.classifyConnection(conn, app, sni);

                if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTPS) {
                    classificationHits.incrementAndGet();
                }
                return true;
            }
            return false;
        }

        private boolean tryExtractHTTPHost(Types.PacketJob job, Types.Connection conn) {
            if (job.tuple.dstPort != 80) return false;
            if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

            // Assuming HTTPHostExtractor exists
            String host = SniExtractor.HttpHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
            if (host != null) {
                // Using AppType Enum
                Types.AppType app = Types.sniToAppType(host); 
                connTracker.classifyConnection(conn, app, host);

                if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTP) {
                    classificationHits.incrementAndGet();
                }
                return true;
            }
            return false;
        }

        private Types.PacketAction checkRules(Types.PacketJob job, Types.Connection conn) {
            if (ruleManager == null) {
                return Types.PacketAction.FORWARD;
            }

            RuleManager.BlockReason reason = ruleManager.shouldBlock(
                    job.tuple.srcIp,
                    job.tuple.dstPort,
                    conn.appType,
                    conn.sni
            );

            if (reason != null) {
                StringBuilder ss = new StringBuilder("[FP").append(fpId).append("] BLOCKED packet: ");
                switch (reason.type) {
                    case IP: ss.append("IP ").append(reason.detail); break;
                    case APP: ss.append("App ").append(reason.detail); break;
                    case DOMAIN: ss.append("Domain ").append(reason.detail); break;
                    case PORT: ss.append("Port ").append(reason.detail); break;
                }
                System.out.println(ss.toString());

                connTracker.blockConnection(conn);
                return Types.PacketAction.DROP;
            }
            return Types.PacketAction.FORWARD;
        }

        private void updateTCPState(Types.Connection conn, byte tcpFlags) {
            final int SYN = 0x02;
            final int ACK = 0x10;
            final int FIN = 0x01;
            final int RST = 0x04;

            if ((tcpFlags & SYN) != 0) {
                if ((tcpFlags & ACK) != 0) {
                    conn.synAckSeen = true;
                } else {
                    conn.synSeen = true;
                }
            }

            if (conn.synSeen && conn.synAckSeen && ((tcpFlags & ACK) != 0)) {
                if (conn.state == Types.ConnectionState.NEW) {
                    conn.state = Types.ConnectionState.ESTABLISHED;
                }
            }

            if ((tcpFlags & FIN) != 0) {
                conn.finSeen = true;
            }

            if ((tcpFlags & RST) != 0) {
                conn.state = Types.ConnectionState.CLOSED;
            }

            if (conn.finSeen && ((tcpFlags & ACK) != 0)) {
                conn.state = Types.ConnectionState.CLOSED;
            }
        }

        public FPStats getStats() {
            FPStats stats = new FPStats();
            stats.packetsProcessed = packetsProcessed.get();
            stats.packetsForwarded = packetsForwarded.get();
            stats.packetsDropped = packetsDropped.get();
            stats.connectionsTracked = connTracker.getActiveCount();
            stats.sniExtractions = sniExtractions.get();
            stats.classificationHits = classificationHits.get();
            return stats;
        }
    }

    // ============================================================================
    // FP Manager - Creates and manages multiple FP threads
    // ============================================================================
    public static class FPManager {

        public static class AggregatedStats {
            public long totalProcessed;
            public long totalForwarded;
            public long totalDropped;
            public long totalConnections;
        }

        private final List<FastPathProcessor> fps;

        public FPManager(int numFps, RuleManager ruleManager, PacketOutputCallback outputCallback) {
            fps = new ArrayList<>(numFps);
            for (int i = 0; i < numFps; i++) {
                fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
            }
            System.out.println("[FPManager] Created " + numFps + " fast path processors");
        }

        public void startAll() {
            for (FastPathProcessor fp : fps) {
                fp.start();
            }
        }

        public void stopAll() {
            for (FastPathProcessor fp : fps) {
                fp.stop();
            }
        }

        public FastPathProcessor getFP(int id) {
            return fps.get(id);
        }

        public LinkedBlockingQueue<Types.PacketJob> getFPQueue(int id) {
            return fps.get(id).getInputQueue();
        }

        public List<LinkedBlockingQueue<Types.PacketJob>> getQueues() {
            List<LinkedBlockingQueue<Types.PacketJob>> queues = new ArrayList<>();
            for (FastPathProcessor fp : fps) {
                queues.add(fp.getInputQueue());
            }
            return queues;
        }

        public int getNumFPs() {
            return fps.size();
        }

        public AggregatedStats getAggregatedStats() {
            AggregatedStats stats = new AggregatedStats();
            for (FastPathProcessor fp : fps) {
                FastPathProcessor.FPStats fpStats = fp.getStats();
                stats.totalProcessed += fpStats.packetsProcessed;
                stats.totalForwarded += fpStats.packetsForwarded;
                stats.totalDropped += fpStats.packetsDropped;
                stats.totalConnections += fpStats.connectionsTracked;
            }
            return stats;
        }

        public String generateClassificationReport() {
            // Updated to use AppType Enum directly
            Map<Types.AppType, Long> appCounts = new HashMap<>();
            Map<String, Long> domainCounts = new HashMap<>();
            long[] stats = new long[2]; // [0] = classified, [1] = unknown

            for (FastPathProcessor fp : fps) {
                fp.getConnectionTracker().forEach(conn -> {
                    appCounts.put(conn.appType, appCounts.getOrDefault(conn.appType, 0L) + 1);

                    if (conn.appType == Types.AppType.UNKNOWN) {
                        stats[1]++;
                    } else {
                        stats[0]++;
                    }

                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1);
                    }
                });
            }

            long totalClassified = stats[0];
            long totalUnknown = stats[1];
            long total = totalClassified + totalUnknown;

            double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
            double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

            StringBuilder ss = new StringBuilder();
            ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
            ss.append("║                 APPLICATION CLASSIFICATION REPORT            ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            ss.append(String.format("║ Total Connections:    %-10d                           ║\n", total));
            ss.append(String.format("║ Classified:           %-10d (%5.1f%%)                  ║\n", totalClassified, classifiedPct));
            ss.append(String.format("║ Unidentified:         %-10d (%5.1f%%)                  ║\n", totalUnknown, unknownPct));

            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                    APPLICATION DISTRIBUTION                  ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            // Updated List to match AppType Map
            List<Map.Entry<Types.AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
            sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            for (Map.Entry<Types.AppType, Long> pair : sortedApps) {
                double pct = total > 0 ? (100.0 * pair.getValue() / total) : 0;
                int barLen = (int) (pct / 5);
                
                StringBuilder bar = new StringBuilder();
                for (int i = 0; i < barLen; i++) bar.append("#");

                // Use Java's native .name() instead of C++ style string converter
                String appName = pair.getKey().name();
                ss.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║\n", appName, pair.getValue(), pct, bar.toString()));
            }

            ss.append("╚══════════════════════════════════════════════════════════════╝\n");
            return ss.toString();
        }
    }
}