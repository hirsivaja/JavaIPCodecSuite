package com.github.hirsivaja.ip;

import org.junit.Assert;
import org.junit.Test;

public class IpUtilsTest {

    @Test
    public void checksumTest() {
        byte[] data = TestUtils.parseHexBinary("E34F2396442799F3");
        short expected = 0x1AFF;
        short actual = IpUtils.calculateInternetChecksum(data);
        Assert.assertEquals(expected, actual);

        data = TestUtils.parseHexBinary("0001F203F4F5F6F7");
        expected = 0x220D;
        actual = IpUtils.calculateInternetChecksum(data);
        Assert.assertEquals(expected, actual);
    }
}
