package com.github.hirsivaja.ip;

import java.nio.ByteBuffer;

public class IpUtils {
    private IpUtils() {}

    public static short calculateInternetChecksum(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        long sum = 0;
        while(buf.hasRemaining()) {
            if(buf.remaining() > 1) {
                sum += buf.getShort() & 0xFFFF;
            } else {
                sum += buf.get() << 8 & 0xFFFF;
            }
        }
        return (short) ((~((sum & 0xFFFF) + (sum >> 16))) & 0xFFFF);
    }
}
