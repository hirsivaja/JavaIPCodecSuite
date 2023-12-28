package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class TcpHeaderTest {

    @Test
    public void tcpTest() {
        byte[] tcpBytes = TestUtils.parseHexBinary("0507005022EC582E3AC018C550104248B8B30000");
        TcpHeader header = TcpHeader.decode(ByteBuffer.wrap(tcpBytes));

        Assert.assertArrayEquals(tcpBytes, TestUtils.toBytes(header));
    }

    @Test
    public void tcpOptionsTest() {
        byte[] tcpBytes = TestUtils.parseHexBinary("A9A01F90021B638DBA311E8E801800CFC92E00000101080A801DA522801DA522");
        TcpHeader header = TcpHeader.decode(ByteBuffer.wrap(tcpBytes));

        Assert.assertArrayEquals(tcpBytes, TestUtils.toBytes(header));
    }
}
