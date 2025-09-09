package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class UdpHeaderTest {

    @Test
    public void udpTest() {
        byte[] udpBytes = IpUtils.parseHexBinary("823456780123ABCD");
        UdpHeader header = UdpHeader.decode(ByteBuffer.wrap(udpBytes));
        Assert.assertEquals(0x8234, header.uSrcPort());
        Assert.assertEquals(0x5678, header.uDstPort());
        Assert.assertEquals((short) 0x8234, header.srcPort());
        Assert.assertEquals((short) 0x5678, header.dstPort());
        Assert.assertEquals(0x0123, header.dataLength());
        Assert.assertEquals((short) 0xABCD, header.checksum());

        Assert.assertArrayEquals(udpBytes, TestUtils.toBytes(header));
    }
}
