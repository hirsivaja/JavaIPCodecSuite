package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Icmpv6PayloadTest {
    @Test
    public void rplTest() {
        byte[] rplBytes = IpUtils.parseHexBinary("6000000000563A40FE80000000000000020A000A000A000AFF02000000000000000000000000001A9B010DD11EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C");
        IpPayload ipv6Payload = Ipv6Payload.decode(ByteBuffer.wrap(rplBytes));

        Assert.assertArrayEquals(rplBytes, TestUtils.toBytes(ipv6Payload));
    }

    @Test
    public void echoRequestTest() {
        byte[] reqBytes = IpUtils.parseHexBinary("6000000000103A403FFE050700000001020086FFFE0580DA3FFE050100001001000000000000000280003F697620010002C9E73637430600");
        IpPayload ipv6Payload = Ipv6Payload.decode(ByteBuffer.wrap(reqBytes));

        Assert.assertTrue(ipv6Payload instanceof Icmpv6Payload);
        Assert.assertTrue(((Icmpv6Payload) ipv6Payload).getMessage() instanceof EchoRequest);
        Assert.assertEquals(0x7620, ((EchoRequest) ((Icmpv6Payload) ipv6Payload).getMessage()).getIdentifier());
        Assert.assertEquals(0x0100, ((EchoRequest) ((Icmpv6Payload) ipv6Payload).getMessage()).getSequenceNumber());
        Assert.assertEquals(16, ((Icmpv6Payload) ipv6Payload).getMessage().getLength());
        Assert.assertEquals(56, ipv6Payload.getLength());

        Assert.assertArrayEquals(reqBytes, TestUtils.toBytes(ipv6Payload));
    }

    @Test
    public void echoResponseTest() {
        byte[] rspBytes = IpUtils.parseHexBinary("6000000000103A3B3FFE05010000100100000000000000023FFE050700000001020086FFFE0580DA81003E697620010002C9E73637430600");
        IpPayload ipv6Payload = Ipv6Payload.decode(ByteBuffer.wrap(rspBytes));

        Assert.assertTrue(ipv6Payload instanceof Icmpv6Payload);
        Assert.assertTrue(((Icmpv6Payload) ipv6Payload).getMessage() instanceof EchoResponse);
        Assert.assertEquals(0x7620, ((EchoResponse) ((Icmpv6Payload) ipv6Payload).getMessage()).getIdentifier());
        Assert.assertEquals(0x0100, ((EchoResponse) ((Icmpv6Payload) ipv6Payload).getMessage()).getSequenceNumber());

        Assert.assertArrayEquals(rspBytes, TestUtils.toBytes(ipv6Payload));
    }

    @Test
    public void destinationUnreachableTest() {
        byte[] duBytes = IpUtils.parseHexBinary("6000000000443A3D3FFE05010410000002C0DFFFFE47033E3FFE050700000001020086FFFE0580DA010413520000000060000000001411013FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033EA07582A40014CF470A040000F9C8E7369D250B00");
        IpPayload ipv6Payload = Ipv6Payload.decode(ByteBuffer.wrap(duBytes));

        Assert.assertTrue(ipv6Payload instanceof Icmpv6Payload);
        Assert.assertTrue(((Icmpv6Payload) ipv6Payload).getMessage() instanceof DestinationUnreachable);
        Assert.assertEquals(0x0000, ((DestinationUnreachable) ((Icmpv6Payload) ipv6Payload).getMessage()).getNextHopMtu());

        Assert.assertArrayEquals(duBytes, TestUtils.toBytes(ipv6Payload));
    }

    @Test
    public void timeExceededTest() {
        byte[] teBytes = IpUtils.parseHexBinary("6000000000443A403FFE050700000001026097FFFE0769EA3FFE050700000001020086FFFE0580DA0300F7520000000060000000001411013FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033EA075829C0014EC4B02010000F9C8E7368A2C0900");
        IpPayload ipv6Payload = Ipv6Payload.decode(ByteBuffer.wrap(teBytes));

        Assert.assertTrue(ipv6Payload instanceof Icmpv6Payload);
        Assert.assertTrue(((Icmpv6Payload) ipv6Payload).getMessage() instanceof TimeExceeded);
        Assert.assertEquals(0, ((Icmpv6Payload) ipv6Payload).getMessage().getCode());

        Assert.assertArrayEquals(teBytes, TestUtils.toBytes(ipv6Payload));
    }
}
