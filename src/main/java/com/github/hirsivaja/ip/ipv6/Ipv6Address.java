package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpAddress;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Ipv6Address implements IpAddress {
    public static final int IPV6_ADDRESS_LEN = 16;
    private final byte[] addressBytes;

    public Ipv6Address(byte[] addressBytes) {
        if (addressBytes.length != IPV6_ADDRESS_LEN) {
            throw new IllegalArgumentException("Incorrect length for IPv6 address " + addressBytes.length);
        }
        this.addressBytes = addressBytes;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(addressBytes);
    }

    @Override
    public int getLength() {
        return IPV6_ADDRESS_LEN;
    }

    @Override
    public byte[] getAddress() {
        return addressBytes;
    }

    @Override
    public InetAddress toInetAddress() {
        try {
            return InetAddress.getByAddress(addressBytes);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Not a valid IPv6 address!", e);
        }
    }

    public Inet6Address toInet6Address() {
        return (Inet6Address) toInetAddress();
    }

    public static Ipv6Address decode(ByteBuffer in) {
        if (in.remaining() < IPV6_ADDRESS_LEN) {
            throw new IllegalArgumentException("Too few remaining bytes " + in.remaining());
        }
        byte[] addressBytes = new byte[IPV6_ADDRESS_LEN];
        in.get(addressBytes);
        return new Ipv6Address(addressBytes);
    }

    /**
     * Returns the compressed IPv6 string representation (RFC 5952)
     * <br>
     * Examples: ::1, 2001:db8::1
     */
    public String toCompressedString() {
        // Convert bytes to 16-bit groups
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((addressBytes[i * 2] & 0xFF) << 8) | (addressBytes[i * 2 + 1] & 0xFF);
        }

        // Find the longest sequence of consecutive zeros
        int longestZeroStart = -1;
        int longestZeroLength = 0;
        int currentZeroStart = -1;
        int currentZeroLength = 0;

        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (currentZeroStart == -1) {
                    currentZeroStart = i;
                    currentZeroLength = 1;
                } else {
                    currentZeroLength++;
                }
            } else {
                if (currentZeroLength > longestZeroLength) {
                    longestZeroStart = currentZeroStart;
                    longestZeroLength = currentZeroLength;
                }
                currentZeroStart = -1;
                currentZeroLength = 0;
            }
        }

        // Check if the last sequence is the longest
        if (currentZeroLength > longestZeroLength) {
            longestZeroStart = currentZeroStart;
            longestZeroLength = currentZeroLength;
        }

        // Build the compressed string
        StringBuilder sb = new StringBuilder();

        // Only compress if we have 2 or more consecutive zeros
        if (longestZeroLength >= 2) {
            // Before the compressed section
            for (int i = 0; i < longestZeroStart; i++) {
                if (i > 0)
                    sb.append(':');
                sb.append(Integer.toHexString(groups[i]));
            }

            // The compressed section
            sb.append("::");

            // After the compressed section
            for (int i = longestZeroStart + longestZeroLength; i < 8; i++) {
                if (i > longestZeroStart + longestZeroLength)
                    sb.append(':');
                sb.append(Integer.toHexString(groups[i]));
            }
        } else {
            // No compression needed
            for (int i = 0; i < 8; i++) {
                if (i > 0)
                    sb.append(':');
                sb.append(Integer.toHexString(groups[i]));
            }
        }
        return sb.toString();
    }

    /**
     * Returns the full uncompressed IPv6 string representation
     * <br>
     * Example: 2001:0db8:0000:0000:0000:0000:0000:0001
     */
    public String toFullString() {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 8; i++) {
            if (i > 0)
                sb.append(':');

            int group = ((addressBytes[i * 2] & 0xFF) << 8) | (addressBytes[i * 2 + 1] & 0xFF);
            sb.append(String.format("%04x", group));
        }
        return sb.toString();
    }

    /**
     * Default string representation uses compressed format
     */
    @Override
    public String toString() {
        return toCompressedString();
    }

}
