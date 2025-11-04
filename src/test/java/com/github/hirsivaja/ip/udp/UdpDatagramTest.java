package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class UdpDatagramTest {

    @Test
    public void udpTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("45C0003E000000000111CEEB0A000002E0000002");
        Ipv4Header header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] udpBytes = IpUtils.parseHexBinary("02860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866");
        UdpDatagram datagram = UdpDatagram.decode(ByteBuffer.wrap(udpBytes), true, header);

        UdpHeader udpHeader = datagram.udpHeader();
        Assert.assertEquals(646, udpHeader.srcPort());
        Assert.assertEquals(646, udpHeader.dstPort());
        Assert.assertEquals(34, datagram.rawData().length);

        byte[] outBytes = TestUtils.toBytes(datagram);
        Assert.assertArrayEquals(udpBytes, outBytes);
    }

    @Test
    public void instantiationTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("45C0003E000000000111CEEB0A000002E0000002");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] udpData = IpUtils.parseHexBinary("02860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866");
        UdpDatagram datagram1 = new UdpDatagram((short) 7876, (short) 2000, udpData, ipv4Header);
        UdpHeader udpHeader1 = datagram1.udpHeader();

        Assert.assertEquals(7876, udpHeader1.srcPort());
        Assert.assertEquals(2000, udpHeader1.dstPort());
        Assert.assertEquals(50, udpHeader1.len());
        Assert.assertEquals(50, datagram1.length());
        Assert.assertEquals((short) 0xD939, udpHeader1.checksum());
        Assert.assertEquals(42, datagram1.data().length());

        UdpDatagram datagram2 = new UdpDatagram(new UdpHeader((short) 7876, (short) 2000, (short) 50, (short) 0), udpData, ipv4Header);
        UdpHeader udpHeader2 = datagram2.udpHeader();

        Assert.assertEquals(7876, udpHeader2.srcPort());
        Assert.assertEquals(2000, udpHeader2.dstPort());
        Assert.assertEquals(50, udpHeader2.len());
        Assert.assertEquals(50, datagram2.length());
        Assert.assertEquals((short) 0xD939, udpHeader2.checksum());
        Assert.assertEquals(42, datagram2.data().length());
    }
}
