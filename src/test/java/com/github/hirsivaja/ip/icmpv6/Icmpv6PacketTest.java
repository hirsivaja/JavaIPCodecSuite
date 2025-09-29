package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Icmpv6PacketTest {
    @Test
    public void rplTest() {
        byte[] rplBytes = IpUtils.parseHexBinary("6000000000563A40FE80000000000000020A000A000A000AFF02000000000000000000000000001A9B010DD11EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C");
        IpPacket packet = Ipv6Packet.decode(ByteBuffer.wrap(rplBytes));

        Assert.assertArrayEquals(rplBytes, TestUtils.toBytes(packet));
    }

    @Test
    public void echoRequestTest() {
        byte[] reqBytes = IpUtils.parseHexBinary("6000000000103A403FFE050700000001020086FFFE0580DA3FFE050100001001000000000000000280003F697620010002C9E73637430600");
        IpPacket packet = Ipv6Packet.decode(ByteBuffer.wrap(reqBytes));

        Assert.assertTrue(packet instanceof Icmpv6Packet);
        Assert.assertTrue(((Icmpv6Packet) packet).message() instanceof EchoRequest);
        Assert.assertEquals(0x7620, ((EchoRequest) ((Icmpv6Packet) packet).message()).identifier());
        Assert.assertEquals(0x0100, ((EchoRequest) ((Icmpv6Packet) packet).message()).sequenceNumber());
        Assert.assertEquals(16, ((Icmpv6Packet) packet).message().length());
        Assert.assertEquals(56, packet.length());
        Assert.assertNotNull(((Icmpv6Packet) packet).ipv6Header());

        Assert.assertArrayEquals(reqBytes, TestUtils.toBytes(packet));
    }

    @Test
    public void echoResponseTest() {
        byte[] rspBytes = IpUtils.parseHexBinary("6000000000103A3B3FFE05010000100100000000000000023FFE050700000001020086FFFE0580DA81003E697620010002C9E73637430600");
        IpPacket packet = Ipv6Packet.decode(ByteBuffer.wrap(rspBytes));

        Assert.assertTrue(packet instanceof Icmpv6Packet);
        Assert.assertTrue(((Icmpv6Packet) packet).message() instanceof EchoResponse);
        Assert.assertEquals(0x7620, ((EchoResponse) ((Icmpv6Packet) packet).message()).identifier());
        Assert.assertEquals(0x0100, ((EchoResponse) ((Icmpv6Packet) packet).message()).sequenceNumber());

        Assert.assertArrayEquals(rspBytes, TestUtils.toBytes(packet));
    }

    @Test
    public void destinationUnreachableTest() {
        byte[] duBytes = IpUtils.parseHexBinary("6000000000443A3D3FFE05010410000002C0DFFFFE47033E3FFE050700000001020086FFFE0580DA010413520000000060000000001411013FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033EA07582A40014CF470A040000F9C8E7369D250B00");
        IpPacket packet = Ipv6Packet.decode(ByteBuffer.wrap(duBytes));

        Assert.assertTrue(packet instanceof Icmpv6Packet);
        Assert.assertTrue(((Icmpv6Packet) packet).message() instanceof DestinationUnreachable);
        Assert.assertEquals(0x0000, ((DestinationUnreachable) ((Icmpv6Packet) packet).message()).nextHopMtu());

        Assert.assertArrayEquals(duBytes, TestUtils.toBytes(packet));
    }

    @Test
    public void timeExceededTest() {
        byte[] teBytes = IpUtils.parseHexBinary("6000000000443A403FFE050700000001026097FFFE0769EA3FFE050700000001020086FFFE0580DA0300F7520000000060000000001411013FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033EA075829C0014EC4B02010000F9C8E7368A2C0900");
        IpPacket packet = Ipv6Packet.decode(ByteBuffer.wrap(teBytes));

        Assert.assertTrue(packet instanceof Icmpv6Packet);
        Assert.assertTrue(((Icmpv6Packet) packet).message() instanceof TimeExceeded);
        Assert.assertEquals(0, ((Icmpv6Packet) packet).message().code().code());

        Assert.assertArrayEquals(teBytes, TestUtils.toBytes(packet));
    }
}
