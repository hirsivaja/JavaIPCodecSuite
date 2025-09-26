package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.tcp.option.TcpOptionType;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class TcpHeaderTest {

    @Test
    public void tcpTest() {
        byte[] tcpBytes = IpUtils.parseHexBinary("8507005022EC582E3AC018C550104248B8B30000");
        TcpHeader header = TcpHeader.decode(ByteBuffer.wrap(tcpBytes));

        Assert.assertEquals(34055, header.uSrcPort());
        Assert.assertEquals(80, header.uDstPort());
        Assert.assertEquals(-31481, header.srcPort());
        Assert.assertEquals((short) 34055, header.srcPort());
        Assert.assertEquals(80, header.dstPort());
        Assert.assertArrayEquals(tcpBytes, TestUtils.toBytes(header));
    }

    @Test
    public void tcpOptionsTest() {
        byte[] tcpBytes = IpUtils.parseHexBinary("A9A01F90021B638DBA311E8E801800CFC92E00000101080A801DA522801DA522");
        TcpHeader header = TcpHeader.decode(ByteBuffer.wrap(tcpBytes));

        Assert.assertArrayEquals(tcpBytes, TestUtils.toBytes(header));
        Assert.assertEquals(3, header.options().size());
        Assert.assertEquals(TcpOptionType.NO_OPERATION, header.options().get(0).optionType());
        Assert.assertEquals(TcpOptionType.NO_OPERATION, header.options().get(1).optionType());
        Assert.assertEquals(TcpOptionType.TIMESTAMPS, header.options().get(2).optionType());
    }
}
