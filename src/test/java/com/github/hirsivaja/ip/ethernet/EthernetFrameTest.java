package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class EthernetFrameTest {

    @Test
    public void arpPacketTest() {
        byte[] ethernetBytes = IpUtils.parseHexBinary("FFFFFFFFFFFFC80E147E339F08060001080006040001C80E147E339FC0A80701000000000000C0A8074E0000000000000000000000000000000000002EBA6C95");
        EthernetFrame ethernetFrame = EthernetFrame.fromBytes(ethernetBytes);

        Assert.assertEquals(6, ethernetFrame.destination().length());
        Assert.assertEquals(6, ethernetFrame.source().toBytes().length);
        Assert.assertFalse(ethernetFrame.hasDot1qTag());
        Assert.assertEquals(0, ethernetFrame.dot1qTag());
        Assert.assertEquals(28, ethernetFrame.payload().length());
        Assert.assertEquals(0x2EBA6C95, ethernetFrame.crc());

        Assert.assertArrayEquals(ethernetBytes, ethernetFrame.toBytes());
    }

    @Test
    public void ipv4PacketTest() {
        String ethernetString = "001A6CA12B99001E7A793F11810000790800450000288A2B0000FF01BF54C0A87902C0A878010D00CF5000090008044B1F530000000000000000000000000000";
        EthernetFrame ethernetFrame = EthernetFrame.fromByteString(ethernetString);

        Assert.assertEquals(6, ethernetFrame.destination().length());
        Assert.assertEquals(6, ethernetFrame.source().length());
        Assert.assertTrue(ethernetFrame.hasDot1qTag());
        Assert.assertEquals(0x0079, ethernetFrame.dot1qTag());
        Assert.assertEquals(40, ethernetFrame.payload().length());
        Assert.assertEquals(0, ethernetFrame.crc());

        Assert.assertEquals(ethernetString, ethernetFrame.toByteString());
    }

    @Test
    public void ipv6PacketTest() {
        byte[] ethernetBytes = IpUtils.parseHexBinary("001E7A793F110014699E11418100007986DD610F01340014063E2003005160120110000000000B15002220030051601201210000000000000002EDDC0016B82653A53A17C9235010CB94D90F0000");
        EthernetFrame ethernetFrame = EthernetFrame.decode(ByteBuffer.wrap(ethernetBytes));

        Assert.assertEquals(6, ethernetFrame.destination().length());
        Assert.assertEquals(6, ethernetFrame.source().length());
        Assert.assertTrue(ethernetFrame.hasDot1qTag());
        Assert.assertEquals(0x0079, ethernetFrame.dot1qTag());
        Assert.assertEquals(60, ethernetFrame.payload().length());
        Assert.assertEquals(0, ethernetFrame.crc());

        Assert.assertArrayEquals(ethernetBytes, TestUtils.toBytes(ethernetFrame));
    }

    @Test
    public void arpWithoutPaddingTest() {
        byte[] ethernetBytes = IpUtils.parseHexBinary("D42122765B7800216A2D3B8E0806000108000604000200216A2D3B8EC0A80266D42122765B78C0A80201");
        EthernetFrame ethernetFrame = EthernetFrame.fromBytes(ethernetBytes);

        Assert.assertNotNull(ethernetFrame);
        Assert.assertTrue(ethernetFrame.payload() instanceof ArpPacket);
    }
}
