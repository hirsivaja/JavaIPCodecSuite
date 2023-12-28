package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv4HeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv4HeaderBytes = TestUtils.parseHexBinary("4500002B50A340007F06C894C0A83801AC1E3DCD");
        Ipv4Header header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));

        Assert.assertArrayEquals(ipv4HeaderBytes, TestUtils.toBytes(header));
    }
}
