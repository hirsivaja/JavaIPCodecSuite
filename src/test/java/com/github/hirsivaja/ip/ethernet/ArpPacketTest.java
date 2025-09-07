package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class ArpPacketTest {

    @Test
    public void arpPacketTest() {
        byte[] arpBytes = IpUtils.parseHexBinary("0001080006040001C80E147E339FC0A80701000000000000C0A8071D");
        ArpPacket arpPacket = ArpPacket.decode(ByteBuffer.wrap(arpBytes));

        Assert.assertEquals(1, arpPacket.operation());
        Assert.assertEquals(6, arpPacket.senderHwAddress().length());
        Assert.assertEquals(4, arpPacket.senderProtocolAddress().length());
        Assert.assertEquals(6, arpPacket.targetHwAddress().length());
        Assert.assertEquals(4, arpPacket.targetProtocolAddress().length());

        Assert.assertArrayEquals(arpBytes, TestUtils.toBytes(arpPacket));
    }
}
