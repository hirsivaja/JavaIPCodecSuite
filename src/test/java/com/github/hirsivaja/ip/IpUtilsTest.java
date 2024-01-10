package com.github.hirsivaja.ip;

import org.junit.Assert;
import org.junit.Test;

public class IpUtilsTest {

    @Test
    public void checksumTest() {
        byte[] data = IpUtils.parseHexBinary("E34F2396442799F3");
        byte[] fullData = IpUtils.parseHexBinary("E34F2396442799F31AFF");
        short expected = 0x1AFF;
        short actual = IpUtils.calculateInternetChecksum(data);
        Assert.assertEquals(expected, actual);
        Assert.assertTrue(IpUtils.verifyInternetChecksum(data, actual));
        Assert.assertTrue(IpUtils.verifyInternetChecksum(fullData));

        data = IpUtils.parseHexBinary("0001F203F4F5F6F7");
        fullData = IpUtils.parseHexBinary("0001F203F4F5F6F7220D");
        expected = 0x220D;
        actual = IpUtils.calculateInternetChecksum(data);
        Assert.assertEquals(expected, actual);
        Assert.assertFalse(IpUtils.verifyInternetChecksum(data, (short) 1));
        Assert.assertTrue(IpUtils.verifyInternetChecksum(fullData));
    }

    @Test
    public void parseHexBinaryTest() {
        String testString = "00010203040506078090A0B0C0D0E0F0";
        byte[] testBytes = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                (byte) 0x80, (byte) 0x90, (byte) 0xA0, (byte) 0xB0, (byte) 0xC0, (byte) 0xD0, (byte) 0xE0, (byte) 0xF0};
        Assert.assertArrayEquals(testBytes, IpUtils.parseHexBinary(testString));
    }

    @Test
    public void printHexBinaryTest() {
        String testString = "001020304050607008090A0B0C0D0E0F";
        byte[] testBytes = new byte[]{ 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        Assert.assertEquals(testString, IpUtils.printHexBinary(testBytes));
    }
}
