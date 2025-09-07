package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.EcnCodePoint;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv6HeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv6HeaderBytes = IpUtils.parseHexBinary("60000000001411043FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033E");
        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(ipv6HeaderBytes));

        Assert.assertEquals((byte) 0x00, header.dscp());
        Assert.assertEquals((byte) 0x00, header.ecn().type());
        Assert.assertEquals(0x00, header.flowLabel());
        Assert.assertEquals(0x0014, header.payloadOnlyLength());
        Assert.assertEquals(0x003C, header.totalLength());
        Assert.assertEquals(0x11, header.nextHeader().type());
        Assert.assertEquals((byte) 0x04, header.hopLimit());
        Assert.assertEquals(0, header.extensionHeaders().size());
        Assert.assertArrayEquals(IpUtils.parseHexBinary("3FFE050700000001020086FFFE0580DA"), header.sourceAddress().rawAddress());
        Assert.assertArrayEquals(IpUtils.parseHexBinary("3FFE05010410000002C0DFFFFE47033E"), header.destinationAddress().rawAddress());

        Assert.assertArrayEquals(ipv6HeaderBytes, TestUtils.toBytes(header));
    }

    @Test
    public void pseudoHeaderTest() {
        byte[] sourceAddress = IpUtils.parseHexBinary("12345452362345234511234214334532");
        byte[] destinationAddress = IpUtils.parseHexBinary("75242334234234234412341232342342");
        short len = 0x1234;
        IpProtocol nextHeader =  IpProtocol.Type.NO_NEXT;

        Ipv6Header ipv6Header = new Ipv6Header((byte) 0, EcnCodePoint.NO_ECN_NO_ECT, 0, len, nextHeader, (byte) 0, new Ipv6Address(sourceAddress), new Ipv6Address(destinationAddress));

        byte[] headerBytes = IpUtils.parseHexBinary("1234545236234523451123421433453275242334234234234412341232342342000012340000003B");
        Assert.assertArrayEquals(headerBytes, ipv6Header.generatePseudoHeader());
    }
}
