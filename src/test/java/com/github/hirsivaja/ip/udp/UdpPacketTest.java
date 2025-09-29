package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class UdpPacketTest {

    @Test
    public void udpTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("45C0003E000000000111CEEB0A000002E0000002");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] udpBytes = IpUtils.parseHexBinary("02860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866");
        UdpPacket packet = (UdpPacket) UdpPacket.decode(ByteBuffer.wrap(udpBytes), ipv4Header);

        UdpHeader udpHeader = packet.udpHeader();
        Assert.assertEquals(646, udpHeader.srcPort());
        Assert.assertEquals(646, udpHeader.dstPort());
        Assert.assertEquals(34, packet.rawData().length);

        byte[] outBytes = TestUtils.toBytes(packet);
        Assert.assertArrayEquals(udpBytes, Arrays.copyOfRange(outBytes, 20, outBytes.length));
    }

    @Test
    public void instantiationTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("45C0003E000000000111CEEB0A000002E0000002");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] udpData = IpUtils.parseHexBinary("02860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866");
        UdpHeader udpHeaderIn = new UdpHeader((short) 7876, (short) 2000, (short) 50);
        UdpPacket packet = new UdpPacket(ipv4Header, udpHeaderIn, udpData);
        UdpHeader udpHeader = packet.datagram().udpHeader();

        Assert.assertEquals(7876, udpHeader.srcPort());
        Assert.assertEquals(2000, udpHeader.dstPort());
        Assert.assertEquals(50, udpHeader.len());
        Assert.assertEquals(50, packet.datagram().length());
        Assert.assertEquals((short) 0xD939, udpHeader.checksum());
        Assert.assertEquals(42, packet.datagram().data().length());
    }
}
