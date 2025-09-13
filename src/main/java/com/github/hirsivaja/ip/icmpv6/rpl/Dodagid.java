package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpUtils;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Destination-Oriented Directed Acyclic Graph Identification
 */
public record Dodagid(ByteArray dodagid) {
    public static final int DODAGID_LEN = 16;

    public Dodagid {
        if(dodagid.array().length != DODAGID_LEN) {
            throw new IllegalArgumentException("Incorrect length for DODAGID " + dodagid.array().length);
        }
    }

    public Dodagid(byte[] dodagidBytes) {
        this(new ByteArray(dodagidBytes));
    }

    public void encode(ByteBuffer out) {
        out.put(dodagid.array());
    }

    public int length() {
        return DODAGID_LEN;
    }

    public byte[] rawDodagid() {
        return dodagid.array();
    }

    @Override
    public String toString() {
        try {
            return this.getClass().getSimpleName() + "[" + InetAddress.getByAddress(dodagid.array()).getHostAddress() + "]";
        } catch (UnknownHostException ignored) {
            // Suppressing the exception
        }
        return this.getClass().getSimpleName() + "[" + IpUtils.printHexBinary(dodagid.array()) + "]";
    }

    public static Dodagid decode(ByteBuffer in) {
        if(in.remaining() < DODAGID_LEN) {
            throw new IllegalArgumentException("Too few remaining bytes " + in.remaining());
        }
        byte[] dodagidBytes = new byte[DODAGID_LEN];
        in.get(dodagidBytes);
        return new Dodagid(dodagidBytes);
    }
}
