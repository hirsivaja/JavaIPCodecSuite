package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.EcnCodePoint;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv4HeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("4500002B50A340007F06C894C0A83801AC1E3DCD");
        Ipv4Header header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));

        Assert.assertArrayEquals(ipv4HeaderBytes, TestUtils.toBytes(header));
    }

    @Test
    public void instantiationTest() {
        Ipv4Header header = new Ipv4Header((byte) 0, EcnCodePoint.NO_ECN_NO_ECT, (short) 0, (short) 0, new Ipv4Flags(false, false, false), (short) 0, (byte) 0, IpProtocols.ARIS, new Ipv4Address(new byte[4]), new Ipv4Address(new byte[4]));
        Assert.assertEquals(0, header.ttl());
    }
}
