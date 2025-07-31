package com.github.hirsivaja.ip;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IpUtils {
    private static final Logger logger = Logger.getLogger("IpUtils");

    private IpUtils() {
    }

    /**
     * Calculates the Internet checksum as defined in RFC 1071.
     *
     * <p>The Internet checksum is computed as the 16-bit one's complement of the
     * one's complement sum of all 16-bit words in the data. This implementation
     * properly handles multiple carries through iterative folding.</p>
     *
     * <p>Algorithm:</p>
     * <ol>
     *   <li>Sum all 16-bit words in the data</li>
     *   <li>Add any odd byte as the high byte of a 16-bit word</li>
     *   <li>Fold carries from bits 16-31 into bits 0-15 until no more carries</li>
     *   <li>Return the one's complement of the result</li>
     * </ol>
     *
     * <p>This checksum is used by IPv4 headers, TCP, UDP, ICMP, and other
     * Internet protocols as specified in their respective RFCs.</p>
     *
     * @param data the byte array to compute the checksum for
     * @return the 16-bit Internet checksum
     * @throws IllegalArgumentException if data is null
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc1071">RFC 1071</a>
     */
    public static short calculateInternetChecksum(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        long sum = 0;

        // Sum all 16-bit words (network byte order - big endian)
        while (buf.hasRemaining()) {
            if (buf.remaining() > 1) {
                // Complete 16-bit word - ByteBuffer.getShort() reads in big-endian (network) order
                sum += buf.getShort() & 0xFFFF;
            } else {
                // Odd byte: treat as high byte of 16-bit word (pad with zero)
                sum += (buf.get() & 0xFF) << 8;
            }
        }

        // Fold carries until no more carries exist (RFC 1071 end-around carry)
        while ((sum & 0xFFFF0000) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }

        // Return one's complement
        return (short) (~sum & 0xFFFF);
    }

    /**
     * Verifies the Internet checksum of data that includes the checksum field.
     *
     * <p>This method verifies that the checksum embedded in the data is correct.
     * The checksum field in the data should contain the actual checksum value.
     * When calculated over the entire data (including the checksum field),
     * the result should be zero for valid data.</p>
     *
     * @param checksumData the byte array containing data with embedded checksum
     * @return true if the checksum is valid (calculation yields zero), false otherwise
     * @throws IllegalArgumentException if checksumData is null
     * @see #calculateInternetChecksum(byte[])
     */
    public static boolean verifyInternetChecksum(byte[] checksumData) {
        return verifyInternetChecksum(checksumData, (short) 0);
    }

    /**
     * Verifies the Internet checksum by comparing the calculated checksum with expected value.
     *
     * <p>This method calculates the checksum of the provided data and compares it
     * with the expected checksum value. The data should NOT include the checksum field
     * when using this method.</p>
     *
     * @param checksumData the byte array to verify (without checksum field)
     * @param expected     the expected checksum value to compare against
     * @return true if the calculated checksum matches the expected value, false otherwise
     * @throws IllegalArgumentException if checksumData is null
     * @see #calculateInternetChecksum(byte[])
     */
    public static boolean verifyInternetChecksum(byte[] checksumData, short expected) {
        short calculated = calculateInternetChecksum(checksumData);
        if (calculated != expected) {
            logger.warning("Checksum mismatch! Expected: 0x" +
                    Integer.toHexString(expected & 0xFFFF) +
                    ", Calculated: 0x" +
                    Integer.toHexString(calculated & 0xFFFF));
        }
        return calculated == expected;
    }

    /**
     * Ensures the Internet checksum of data that includes the checksum field is valid.
     *
     * <p>This method verifies that the checksum embedded in the data is correct
     * and throws an exception if validation fails. The checksum field in the data
     * should contain the actual checksum value. When calculated over the entire data
     * (including the checksum field), the result should be zero for valid data.</p>
     *
     * @param checksumData the byte array containing data with embedded checksum
     * @throws IllegalArgumentException if the checksum is invalid or checksumData is null
     * @see #verifyInternetChecksum(byte[])
     */
    public static void ensureInternetChecksum(byte[] checksumData) {
        ensureInternetChecksum(checksumData, (short) 0);
    }

    /**
     * Ensures the Internet checksum matches the expected value.
     *
     * <p>This method calculates the checksum of the provided data and compares it
     * with the expected checksum value, throwing an exception if they don't match.
     * The data should NOT include the checksum field when using this method.</p>
     *
     * @param checksumData the byte array to verify (without checksum field)
     * @param expected     the expected checksum value
     * @throws IllegalArgumentException if the checksum doesn't match expected value or checksumData is null
     * @see #calculateInternetChecksum(byte[])
     */
    public static void ensureInternetChecksum(byte[] checksumData, short expected) {
        short calculated = calculateInternetChecksum(checksumData);
        if (calculated != expected) {
            logger.log(Level.FINEST, "Checksum mismatch! Expected: 0x{0}, Calculated: 0x{1}",
                    new Object[]{Integer.toHexString(expected & 0xFFFF),
                            Integer.toHexString(calculated & 0xFFFF)});
            throw new IllegalArgumentException("Checksum does not match! Expected: 0x" +
                    Integer.toHexString(expected & 0xFFFF) +
                    ", Calculated: 0x" +
                    Integer.toHexString(calculated & 0xFFFF));
        }
    }

    public static byte[] parseHexBinary(String hexString) {
        if (hexString.length() % 2 == 1) {
            hexString = "0" + hexString;
        }
        char[] chars = hexString.toCharArray();
        byte[] bytes = new byte[chars.length / 2];
        for (int i = 0, j = 0; i < chars.length; i += 2, j++) {
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
