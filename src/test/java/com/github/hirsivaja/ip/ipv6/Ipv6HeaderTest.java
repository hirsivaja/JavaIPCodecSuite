package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv6HeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv6HeaderBytes = TestUtils.parseHexBinary("60000000001411043FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033E");
        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(ipv6HeaderBytes));

        Assert.assertEquals((byte) 0x00, header.getDscp());
        Assert.assertEquals((byte) 0x00, header.getEcn().getType());
        Assert.assertEquals(0x00, header.getFlowLabel());
        Assert.assertEquals(0x0014, header.getPayloadLength());
        Assert.assertEquals(0x11, header.getNextHeader().getType());
        Assert.assertEquals((byte) 0x04, header.getHopLimit());
        Assert.assertArrayEquals(TestUtils.parseHexBinary("3FFE050700000001020086FFFE0580DA"), header.getSourceAddress());
        Assert.assertArrayEquals(TestUtils.parseHexBinary("3FFE05010410000002C0DFFFFE47033E"), header.getDestinationAddress());

        Assert.assertArrayEquals(ipv6HeaderBytes, TestUtils.toBytes(header));
    }

    @Test
    public void pseudoHeaderTest() {
        byte[] sourceAddress = TestUtils.parseHexBinary("12345452362345234511234214334532");
        byte[] destinationAddress = TestUtils.parseHexBinary("75242334234234234412341232342342");
        short len = 0x1234;
        IpProtocol nextHeader =  IpProtocol.NO_NEXT;

        Ipv6Header ipv6Header = new Ipv6Header((byte) 0, IpHeader.EcnCodePoint.NO_ECN_NO_ECT, 0, len, nextHeader, (byte) 0, sourceAddress, destinationAddress);

        byte[] headerBytes = TestUtils.parseHexBinary("1234545236234523451123421433453275242334234234234412341232342342000012340000003B");
        Assert.assertArrayEquals(headerBytes, ipv6Header.getPseudoHeader());
    }
}
