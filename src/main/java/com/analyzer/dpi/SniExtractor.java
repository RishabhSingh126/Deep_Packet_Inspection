package com.analyzer.dpi;

import java.nio.charset.StandardCharsets;

/**
 * Extracts domain names (SNI, HTTP Host, DNS) from raw packet payloads.
 * Merged from sni_extractor.h and sni_extractor.cpp
 */
public class SniExtractor {

    // ============================================================================
    // TLS SNI Extractor - Parses TLS Client Hello to extract Server Name Indication
    // ============================================================================
    public static class TlsSniExtractor {
        private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
        private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
        private static final int EXTENSION_SNI = 0x0000;
        private static final int SNI_TYPE_HOSTNAME = 0x00;

        private static int readUint16BE(byte[] data, int offset) {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }

        private static int readUint24BE(byte[] data, int offset) {
            return ((data[offset] & 0xFF) << 16) |
                   ((data[offset + 1] & 0xFF) << 8) |
                   (data[offset + 2] & 0xFF);
        }

        public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
            // Minimum TLS record: 5 bytes header + 4 bytes handshake header
            if (length < 9) return false;
            
            // Byte 0: Content Type (should be 0x16 = Handshake)
            if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
            
            // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
            // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
            int version = readUint16BE(payload, offset + 1);
            if (version < 0x0300 || version > 0x0304) return false;
            
            // Bytes 3-4: Record length
            int recordLength = readUint16BE(payload, offset + 3);
            if (recordLength > length - 5) return false;
            
            // Check handshake header (starts at byte 5)
            // Byte 5: Handshake Type (should be 0x01 = Client Hello)
            if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;
            
            return true;
        }

        public static String extract(byte[] payload, int startOffset, int length) {
            if (!isTLSClientHello(payload, startOffset, length)) {
                return null;
            }
            
            int offset = startOffset + 5; // Skip TLS record header
            
            // Skip handshake header (Byte 0: type, Bytes 1-3: length)
            int handshakeLength = readUint24BE(payload, offset + 1);
            offset += 4;
            
            // Client Hello body
            offset += 2; // Client version
            offset += 32; // Random (32 bytes)
            
            // Session ID
            if (offset - startOffset >= length) return null;
            int sessionIdLength = payload[offset] & 0xFF;
            offset += 1 + sessionIdLength;
            
            // Cipher suites
            if (offset - startOffset + 2 > length) return null;
            int cipherSuitesLength = readUint16BE(payload, offset);
            offset += 2 + cipherSuitesLength;
            
            // Compression methods
            if (offset - startOffset >= length) return null;
            int compressionMethodsLength = payload[offset] & 0xFF;
            offset += 1 + compressionMethodsLength;
            
            // Extensions
            if (offset - startOffset + 2 > length) return null;
            int extensionsLength = readUint16BE(payload, offset);
            offset += 2;
            
            int extensionsEnd = offset + extensionsLength;
            if (extensionsEnd - startOffset > length) {
                extensionsEnd = startOffset + length; // Truncated, but try to parse anyway
            }
            
            // Parse extensions to find SNI
            while (offset + 4 <= extensionsEnd) {
                int extensionType = readUint16BE(payload, offset);
                int extensionLength = readUint16BE(payload, offset + 2);
                offset += 4;
                
                if (offset + extensionLength > extensionsEnd) break;
                
                if (extensionType == EXTENSION_SNI) {
                    if (extensionLength < 5) break;
                    
                    int sniListLength = readUint16BE(payload, offset);
                    if (sniListLength < 3) break;
                    
                    int sniType = payload[offset + 2] & 0xFF;
                    int sniLength = readUint16BE(payload, offset + 3);
                    
                    if (sniType != SNI_TYPE_HOSTNAME) break;
                    if (sniLength > extensionLength - 5) break;
                    
                    // Extract the hostname
                    return new String(payload, offset + 5, sniLength, StandardCharsets.UTF_8);
                }
                
                offset += extensionLength;
            }
            
            return null;
        }
    }

    // ============================================================================
    // HTTP Host Header Extractor (for unencrypted HTTP)
    // ============================================================================
    public static class HttpHostExtractor {
        public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
            if (length < 4) return false;
            
            String method = new String(payload, offset, 4, StandardCharsets.US_ASCII);
            return method.equals("GET ") || method.equals("POST") || 
                   method.equals("PUT ") || method.equals("HEAD") || 
                   method.equals("DELE") || method.equals("PATC") || 
                   method.equals("OPTI");
        }

        public static String extract(byte[] payload, int startOffset, int length) {
            if (!isHTTPRequest(payload, startOffset, length)) {
                return null;
            }
            
            String data = new String(payload, startOffset, length, StandardCharsets.US_ASCII);
            
            // Simple case-insensitive search for "Host:"
            int hostIdx = data.toLowerCase().indexOf("\nhost:");
            if (hostIdx == -1) {
                hostIdx = data.toLowerCase().indexOf("host:");
                if (hostIdx != 0) return null; // Only valid if it's the very first line (rare)
            } else {
                hostIdx += 1; // Skip the newline
            }
            
            int start = hostIdx + 5;
            
            // Skip whitespace
            while (start < length && (data.charAt(start) == ' ' || data.charAt(start) == '\t')) {
                start++;
            }
            
            int end = start;
            while (end < length && data.charAt(end) != '\r' && data.charAt(end) != '\n') {
                end++;
            }
            
            if (end > start) {
                String host = data.substring(start, end);
                int colonPos = host.indexOf(':');
                if (colonPos != -1) {
                    host = host.substring(0, colonPos);
                }
                return host;
            }
            
            return null;
        }
    }

    // ============================================================================
    // DNS Query Extractor
    // ============================================================================
    public static class DnsExtractor {
        public static boolean isDNSQuery(byte[] payload, int offset, int length) {
            if (length < 12) return false;
            
            // Check QR bit (byte 2, bit 7) - should be 0 for query
            int flags = payload[offset + 2] & 0xFF;
            if ((flags & 0x80) != 0) return false;
            
            // Check QDCOUNT (bytes 4-5) - should be > 0
            int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
            return qdcount > 0;
        }

        public static String extractQuery(byte[] payload, int startOffset, int length) {
            if (!isDNSQuery(payload, startOffset, length)) {
                return null;
            }
            
            int offset = startOffset + 12;
            StringBuilder domain = new StringBuilder();
            
            while (offset - startOffset < length) {
                int labelLength = payload[offset] & 0xFF;
                
                if (labelLength == 0) break; // End of domain name
                if (labelLength > 63) break; // Compression pointer or invalid
                
                offset++;
                if (offset - startOffset + labelLength > length) break;
                
                if (domain.length() > 0) {
                    domain.append('.');
                }
                domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
                offset += labelLength;
            }
            
            return domain.length() == 0 ? null : domain.toString();
        }
    }

    // ============================================================================
    // QUIC SNI Extractor
    // ============================================================================
    public static class QuicSniExtractor {
        public static boolean isQUICInitial(byte[] payload, int offset, int length) {
            if (length < 5) return false;
            int firstByte = payload[offset] & 0xFF;
            return (firstByte & 0x80) != 0; // Long header form
        }

        public static String extract(byte[] payload, int startOffset, int length) {
            if (!isQUICInitial(payload, startOffset, length)) {
                return null;
            }
            
            for (int i = 0; i + 50 < length; i++) {
                if ((payload[startOffset + i] & 0xFF) == 0x01) { // Client Hello handshake type
                    // Simplified: Try to extract SNI starting near here
                    int searchOffset = Math.max(startOffset, startOffset + i - 5);
                    int searchLength = length - (searchOffset - startOffset);
                    String result = TlsSniExtractor.extract(payload, searchOffset, searchLength);
                    if (result != null) return result;
                }
            }
            
            return null;
        }
    }
}