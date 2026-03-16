package com.analyzer.dpi;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer - Routes packets to the correct Fast Path processors using consistent hashing.
 * Merged from load_balancer.h and load_balancer.cpp
 */
public class LoadBalancer implements Runnable {

    // ============================================================================
    // Statistics Structures
    // ============================================================================

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public long[] perFpPackets;
    }

    // ============================================================================
    // Instance Variables
    // ============================================================================

    private final int lbId;
    private final int fpStartId;
    private final int numFps;

    // Queues
    private final LinkedBlockingQueue<Types.PacketJob> inputQueue;
    private final List<LinkedBlockingQueue<Types.PacketJob>> fpQueues;

    // Statistics
    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts; // Not shared, only updated by LB thread

    // Thread control
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId, List<LinkedBlockingQueue<Types.PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new LinkedBlockingQueue<>(10000);
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[numFps];
    }

    public void start() {
        if (running.get()) return;

        running.set(true);
        thread = new Thread(this, "LB-Thread-" + lbId);
        thread.start();

        System.out.println("[LB" + lbId + "] Started (serving FP"
                + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {
        if (!running.get()) return;

        running.set(false);
        if (thread != null) {
            thread.interrupt();
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    public LinkedBlockingQueue<Types.PacketJob> getInputQueue() {
        return inputQueue;
    }

    public int getId() {
        return lbId;
    }

    public boolean isRunning() {
        return running.get();
    }

    @Override
    public void run() {
        while (running.get()) {
            try {
                // Poll input queue with timeout
                Types.PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);

                if (job == null) {
                    continue; // Timeout, loop back and check running flag
                }

                packetsReceived.incrementAndGet();

                // Select target FP based on five-tuple hash
                int fpIndex = selectFP(job.tuple);

                // Push to selected FP's queue (blocking if the FP queue is completely full)
                fpQueues.get(fpIndex).put(job);

                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex]++;

            } catch (InterruptedException e) {
                if (!running.get()) break;
            } catch (Exception e) {
                System.err.println("[LB" + lbId + "] Error dispatching packet: " + e.getMessage());
            }
        }
    }

    private int selectFP(Types.FiveTuple tuple) {
        // Hash the tuple and map to one of our FPs.
        // Bitwise AND with 0x7FFFFFFF forces the sign bit to 0, ensuring a positive number.
        int hash = tuple.hashCode() & 0x7FFFFFFF;
        return hash % numFps;
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        // Return a copy to prevent external modification
        stats.perFpPackets = perFpCounts.clone();
        return stats;
    }

    // ============================================================================
    // LB Manager - Creates and manages multiple LB threads
    // ============================================================================

    public static class LBManager {

        public static class AggregatedStats {
            public long totalReceived;
            public long totalDispatched;
        }

        private final List<LoadBalancer> lbs;
        private final int fpsPerLb;

        public LBManager(int numLbs, int fpsPerLb, List<LinkedBlockingQueue<Types.PacketJob>> fpQueues) {
            this.fpsPerLb = fpsPerLb;
            this.lbs = new ArrayList<>(numLbs);

            // Create load balancers, each handling a subset of FPs
            for (int lbId = 0; lbId < numLbs; lbId++) {
                List<LinkedBlockingQueue<Types.PacketJob>> lbFpQueues = new ArrayList<>();
                int fpStart = lbId * fpsPerLb;

                for (int i = 0; i < fpsPerLb; i++) {
                    lbFpQueues.add(fpQueues.get(fpStart + i));
                }

                lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
            }

            System.out.println("[LBManager] Created " + numLbs + " load balancers, "
                    + fpsPerLb + " FPs each");
        }

        public void startAll() {
            for (LoadBalancer lb : lbs) {
                lb.start();
            }
        }

        public void stopAll() {
            for (LoadBalancer lb : lbs) {
                lb.stop();
            }
        }

        public LoadBalancer getLBForPacket(Types.FiveTuple tuple) {
            // First level of load balancing: select LB based on hash
            int hash = tuple.hashCode() & 0x7FFFFFFF;
            int lbIndex = hash % lbs.size();
            return lbs.get(lbIndex);
        }

        public LoadBalancer getLB(int id) {
            return lbs.get(id);
        }

        public int getNumLBs() {
            return lbs.size();
        }

        public AggregatedStats getAggregatedStats() {
            AggregatedStats stats = new AggregatedStats();

            for (LoadBalancer lb : lbs) {
                LBStats lbStats = lb.getStats();
                stats.totalReceived += lbStats.packetsReceived;
                stats.totalDispatched += lbStats.packetsDispatched;
            }

            return stats;
        }
    }
}