package com.github.hirsivaja.ip;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IpUtils {
    private static final Logger logger = Logger.getLogger("IpUtils");
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

    public static boolean verifyInternetChecksum(byte[] checksumData, short actual) {
        return verifyInternetChecksum(calculateInternetChecksum(checksumData), actual);
    }

    public static boolean verifyInternetChecksum(short expected, short actual) {
        if(expected != actual) {
            logger.warning("CRC mismatch!");
        }
        return expected == actual;
    }

    public static void ensureInternetChecksum(byte[] checksumData, short actual) {
        ensureInternetChecksum(calculateInternetChecksum(checksumData), actual);
    }

    public static void ensureInternetChecksum(short expected, short actual) {
        if(expected != actual) {
            logger.log(Level.FINEST, "Checksum mismatch! Expected checksum {0}. Actual checksum {1}", new Object[]{expected, actual});
            throw new IllegalArgumentException("Checksum does not match!");
        }
    }

    public static byte[] parseHexBinary(String hexString) {
        if(hexString.length() % 2 == 1) {
            hexString = "0" + hexString;
        }
        char[] chars = hexString.toCharArray();
        byte[] bytes = new byte[chars.length / 2];
        for(int i = 0, j = 0; i < chars.length; i += 2, j++) {
            int a = Character.digit(chars[i], 16) << 4;
            int b = Character.digit(chars[i + 1], 16);
            bytes[j] = (byte) (a | b);
        }
        return bytes;
    }

    public static String printHexBinary(byte[] hexBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte hexByte : hexBytes) {
            sb.append(String.format("%02x", hexByte));
        }
        return sb.toString().toUpperCase();
    }
}
