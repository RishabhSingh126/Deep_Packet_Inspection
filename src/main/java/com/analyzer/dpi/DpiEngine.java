package com.analyzer.dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DPI Engine - Main orchestrator
 * Merged from dpi_engine.h and dpi_engine.cpp
 */
public class DpiEngine {

    // ============================================================================
    // Configuration
    // ============================================================================
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;

    // Shared components
    private RuleManager ruleManager;
    private ConnectionTracker.GlobalConnectionTable globalConnTable;

    // Thread pools
    private FastPath.FPManager fpManager;
    private LoadBalancer.LBManager lbManager;

    // Output handling
    private final LinkedBlockingQueue<Types.PacketJob> outputQueue;
    private Thread outputThread;
    private FileOutputStream outputStream;
    private final Object outputMutex = new Object();

    // Statistics
    private final Types.DPIStats stats;

    // Control
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);

    // Reader thread
    private Thread readerThread;

    public DpiEngine(Config config) {
        this.config = config;
        this.outputQueue = new LinkedBlockingQueue<>(config.queueSize);
        this.stats = new Types.DPIStats();

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                           ║");
        System.out.println("║               Deep Packet Inspection System                  ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                               ║");
        System.out.printf("║   Load Balancers:    %3d                                     ║\n", config.numLoadBalancers);
        System.out.printf("║   FPs per LB:        %3d                                     ║\n", config.fpsPerLb);
        System.out.printf("║   Total FP threads:  %3d                                     ║\n", (config.numLoadBalancers * config.fpsPerLb));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        // Create rule manager
        ruleManager = new RuleManager();

        // Load rules if specified
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        // Create output callback
        FastPath.PacketOutputCallback outputCb = this::handleOutput;

        // Create FP manager (creates FP threads and their queues)
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FastPath.FPManager(totalFps, ruleManager, outputCb);

        // Create LB manager (creates LB threads, connects to FP queues)
        lbManager = new LoadBalancer.LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueues());

        // Create global connection table
        globalConnTable = new ConnectionTracker.GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        processingComplete.set(false);

        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "Output-Thread");
        outputThread.start();

        // Start FP threads
        fpManager.startAll();

        // Start LB threads
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);

        // Stop LB threads first (they feed FPs)
        if (lbManager != null) {
            lbManager.stopAll();
        }

        // Stop FP threads
        if (fpManager != null) {
            fpManager.stopAll();
        }

        // Stop output thread
        if (outputThread != null) {
            outputThread.interrupt();
            try {
                outputThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        // Wait for reader to finish
        if (readerThread != null && readerThread.isAlive()) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Wait a bit for queues to drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {}

        // Signal completion
        processingComplete.set(true);
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        // Initialize if not already done
        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        // Open output file
        try {
            outputStream = new FileOutputStream(outputFile);
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        // Start processing threads
        start();

        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "Reader-Thread");
        readerThread.start();

        // Wait for completion
        waitForCompletion();

        // Give some time for final packets to process
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {}

        // Stop all threads
        stop();

        // Close output file
        try {
            if (outputStream != null) {
                outputStream.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing output stream.");
        }

        // Print final report
        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());

        return true;
    }

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader();

        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        // Write PCAP header to output
        writeOutputHeader(reader.getGlobalHeader());

        int packetId = 0;
        System.out.println("[Reader] Starting packet processing...");

        PcapReader.RawPacket raw;
        
        // Java style reading
        while ((raw = reader.readNextPacket()) != null) {
            
            // Java style parsing
            PacketParser.ParsedPacket parsed = PacketParser.parse(raw);
            
            if (parsed == null) {
                continue; // Skip unparseable packets
            }

            // Only process IP packets with TCP/UDP
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                continue;
            }

            // Create packet job
            Types.PacketJob job = createPacketJob(raw, parsed, packetId++);

            // Update global stats
            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            if (parsed.hasTcp) {
                stats.tcpPackets.incrementAndGet();
            } else if (parsed.hasUdp) {
                stats.udpPackets.incrementAndGet();
            }

            // Send to appropriate LB based on hash
            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            try {
                lb.getInputQueue().put(job);
            } catch (InterruptedException e) {
                if (!running.get()) break;
            }
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private Types.PacketJob createPacketJob(PcapReader.RawPacket raw, PacketParser.ParsedPacket parsed, int packetId) {
        Types.PacketJob job = new Types.PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;
        job.tuple = new Types.FiveTuple();

        // FIX: Replaced buggy String-to-int parseIP method with direct raw long values from PacketParser
        job.tuple.srcIp = parsed.srcIpRaw;
        job.tuple.dstIp = parsed.destIpRaw;
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;

        // TCP flags
        job.tcpFlags = parsed.tcpFlags;

        // Copy packet data
        job.data = raw.data;

        // Calculate offsets
        job.ethOffset = 0;
        job.ipOffset = 14; // Ethernet header is 14 bytes

        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >>> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8; // UDP header is 8 bytes
            }

            if (job.payloadOffset < job.data.length && job.payloadOffset > 0) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                Types.PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                if (!running.get()) break;
            }
        }
    }

    private void handleOutput(Types.PacketJob job, Types.PacketAction action) {
        if (action == Types.PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }

        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.put(job);
        } catch (InterruptedException ignored) {}
    }

    private boolean writeOutputHeader(PcapReader.PcapGlobalHeader header) {
        synchronized (outputMutex) {
            if (outputStream == null) return false;

            try {
                ByteBuffer bb = ByteBuffer.allocate(24);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt((int) header.magicNumber);
                bb.putShort((short) header.versionMajor); 
                bb.putShort((short) header.versionMinor); 
                bb.putInt((int) header.thiszone);
                bb.putInt((int) header.sigfigs);
                bb.putInt((int) header.snaplen);
                bb.putInt((int) header.network);

                outputStream.write(bb.array());
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    private void writeOutputPacket(Types.PacketJob job) {
        synchronized (outputMutex) {
            if (outputStream == null) return;

            try {
                ByteBuffer bb = ByteBuffer.allocate(16);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt((int) job.tsSec);
                bb.putInt((int) job.tsUsec);
                bb.putInt(job.data.length); // incl_len
                bb.putInt(job.data.length); // orig_len

                outputStream.write(bb.array());
                outputStream.write(job.data);
            } catch (IOException e) {
                System.err.println("Failed writing output packet");
            }
        }
    }

    // ============================================================================
    // Rule Management API
    // ============================================================================

    public void blockIP(String ip) { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void unblockIP(String ip) { if (ruleManager != null) ruleManager.unblockIP(ip); }

    // FIX: Changed to take Types.AppType Enum to match RuleManager
    public void blockApp(Types.AppType app) { if (ruleManager != null) ruleManager.blockApp(app); }
    public void blockApp(String appName) {
        try {
            Types.AppType app = Types.AppType.valueOf(appName.toUpperCase());
            blockApp(app);
        } catch (IllegalArgumentException e) {
            System.err.println("[DPIEngine] Unknown app: " + appName);
        }
    }

    // FIX: Changed to take Types.AppType Enum to match RuleManager
    public void unblockApp(Types.AppType app) { if (ruleManager != null) ruleManager.unblockApp(app); }
    public void unblockApp(String appName) {
        try {
            Types.AppType app = Types.AppType.valueOf(appName.toUpperCase());
            unblockApp(app);
        } catch (IllegalArgumentException e) {
            // Ignore if app doesn't exist when unblocking
        }
    }

    public void blockDomain(String domain) { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain) { if (ruleManager != null) ruleManager.unblockDomain(domain); }

    public boolean loadRules(String filename) { return ruleManager != null && ruleManager.loadRules(filename); }
    public boolean saveRules(String filename) { return ruleManager != null && ruleManager.saveRules(filename); }

    // ============================================================================
    // Reporting
    // ============================================================================

    public String generateReport() {
        StringBuilder ss = new StringBuilder();

        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                     ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append("║ PACKET STATISTICS                                            ║\n");
        ss.append(String.format("║   Total Packets:      %12d                           ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                           ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                           ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                           ║\n", stats.udpPackets.get()));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                         ║\n");
        ss.append(String.format("║   Forwarded:          %12d                           ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                           ║\n", stats.droppedPackets.get()));

        long totalPackets = stats.totalPackets.get();
        if (totalPackets > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / totalPackets;
            ss.append(String.format("║   Drop Rate:          %11.2f%%                           ║\n", dropRate));
        }

        if (lbManager != null) {
            LoadBalancer.LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ LOAD BALANCER STATISTICS                                     ║\n");
            ss.append(String.format("║   LB Received:        %12d                           ║\n", lbStats.totalReceived));
            ss.append(String.format("║   LB Dispatched:      %12d                           ║\n", lbStats.totalDispatched));
        }

        if (fpManager != null) {
            FastPath.FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ FAST PATH STATISTICS                                         ║\n");
            ss.append(String.format("║   FP Processed:       %12d                           ║\n", fpStats.totalProcessed));
            ss.append(String.format("║   FP Forwarded:       %12d                           ║\n", fpStats.totalForwarded));
            ss.append(String.format("║   FP Dropped:         %12d                           ║\n", fpStats.totalDropped));
            ss.append(String.format("║   Active Connections: %12d                           ║\n", fpStats.totalConnections));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                               ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                           ║\n", ruleStats.blockedIps));
            ss.append(String.format("║   Blocked Apps:       %12d                           ║\n", ruleStats.blockedApps));
            ss.append(String.format("║   Blocked Domains:    %12d                           ║\n", ruleStats.blockedDomains));
            ss.append(String.format("║   Blocked Ports:      %12d                           ║\n", ruleStats.blockedPorts));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public Types.DPIStats getStats() {
        return stats;
    }

    public boolean isRunning() {
        return running.get();
    }
}