package com.analyzer.dpi;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads and parses PCAP (Packet Capture) files.
 * Merged from pcap_reader.h and pcap_reader.cpp
 */
public class PcapReader {

    // ============================================================================
    // PCAP Data Structures
    // ============================================================================

    public static class PcapGlobalHeader {
        public long magicNumber;
        public int versionMajor;
        public int versionMinor;
        public int thiszone;
        public long sigfigs;
        public long snaplen;
        public long network; // Data link type (1 = Ethernet)
    }

    public static class PcapPacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;
        public long origLen;
    }

    public static class RawPacket {
        public PcapPacketHeader header;
        public byte[] data;
    }

    // ============================================================================
    // Instance Variables
    // ============================================================================
    private InputStream fileStream;
    private PcapGlobalHeader globalHeader;
    private boolean isLittleEndian = false;

    // ============================================================================
    // Public API
    // ============================================================================

    public boolean open(String filename) {
        close(); // Close any previously opened file

        try {
            fileStream = new BufferedInputStream(new FileInputStream(filename));
            byte[] ghBytes = new byte[24];
            
            int read = fileStream.read(ghBytes);
            if (read < 24) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            globalHeader = new PcapGlobalHeader();
            
            // Check magic number to determine Endianness
            if ((ghBytes[0] & 0xFF) == 0xA1 && (ghBytes[1] & 0xFF) == 0xB2 && 
                (ghBytes[2] & 0xFF) == 0xC3 && (ghBytes[3] & 0xFF) == 0xD4) {
                isLittleEndian = false; // Native Big-Endian
            } else if ((ghBytes[0] & 0xFF) == 0xD4 && (ghBytes[1] & 0xFF) == 0xC3 && 
                       (ghBytes[2] & 0xFF) == 0xB2 && (ghBytes[3] & 0xFF) == 0xA1) {
                isLittleEndian = true;  // Swapped Little-Endian
            } else {
                System.err.println("Error: Invalid PCAP magic number.");
                close();
                return false;
            }

            // Parse the rest of the Global Header
            globalHeader.magicNumber = readUInt32(ghBytes, 0);
            globalHeader.versionMajor = readUInt16(ghBytes, 4);
            globalHeader.versionMinor = readUInt16(ghBytes, 6);
            globalHeader.thiszone = (int) readUInt32(ghBytes, 8); // simplified as int
            globalHeader.sigfigs = readUInt32(ghBytes, 12);
            globalHeader.snaplen = readUInt32(ghBytes, 16);
            globalHeader.network = readUInt32(ghBytes, 20);

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;

        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            e.printStackTrace();
            return false;
        }
    }

    public void close() {
        if (fileStream != null) {
            try {
                fileStream.close();
            } catch (IOException e) {
                // Ignore close exceptions
            }
            fileStream = null;
        }
        isLittleEndian = false;
        globalHeader = null;
    }

    public boolean isOpen() {
        return fileStream != null;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    /**
     * Reads the next packet from the stream.
     * @return RawPacket if successful, or null if end of file/error.
     */
    public RawPacket readNextPacket() {
        if (fileStream == null) return null;

        try {
            byte[] phBytes = new byte[16];
            int read = fileStream.read(phBytes);
            if (read < 16) return null; // EOF or error

            RawPacket packet = new RawPacket();
            packet.header = new PcapPacketHeader();
            
            packet.header.tsSec = readUInt32(phBytes, 0);
            packet.header.tsUsec = readUInt32(phBytes, 4);
            packet.header.inclLen = readUInt32(phBytes, 8);
            packet.header.origLen = readUInt32(phBytes, 12);

            // Sanity check on packet length
            if (packet.header.inclLen > globalHeader.snaplen || packet.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
                return null;
            }

            int lengthToRead = (int) packet.header.inclLen;
            packet.data = new byte[lengthToRead];
            
            int dataRead = 0;
            while (dataRead < lengthToRead) {
                int result = fileStream.read(packet.data, dataRead, lengthToRead - dataRead);
                if (result == -1) {
                    System.err.println("Error: Unexpected EOF while reading packet data");
                    return null;
                }
                dataRead += result;
            }

            return packet;

        } catch (IOException e) {
            System.err.println("Error reading next packet: " + e.getMessage());
            return null;
        }
    }

    // ============================================================================
    // Byte-Order Helpers
    // ============================================================================

    private long readUInt32(byte[] data, int offset) {
        if (isLittleEndian) {
            return ((data[offset + 3] & 0xFFL) << 24) |
                   ((data[offset + 2] & 0xFFL) << 16) |
                   ((data[offset + 1] & 0xFFL) << 8) |
                   ((data[offset] & 0xFFL));
        } else {
            return ((data[offset] & 0xFFL) << 24) |
                   ((data[offset + 1] & 0xFFL) << 16) |
                   ((data[offset + 2] & 0xFFL) << 8) |
                   ((data[offset + 3] & 0xFFL));
        }
    }

    private int readUInt16(byte[] data, int offset) {
        if (isLittleEndian) {
            return ((data[offset + 1] & 0xFF) << 8) |
                   ((data[offset] & 0xFF));
        } else {
            return ((data[offset] & 0xFF) << 8) |
                   ((data[offset + 1] & 0xFF));
        }
    }
}