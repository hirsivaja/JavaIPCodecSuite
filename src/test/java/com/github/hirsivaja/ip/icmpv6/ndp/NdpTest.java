package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class NdpTest {

    @Test
    public void routerSolicitationTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000083AFFFE80000000000000020086FFFE0580DAFF020000000000000000000000000002");
        byte[] msg = IpUtils.parseHexBinary("8500755700000000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        RouterSolicitation rs = (RouterSolicitation) payload.message();

        Assert.assertEquals(0, rs.options().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void routerAdvertisementTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000403AFFFE80000000000000026097FFFE0769EAFF020000000000000000000000000001");
        byte[] msg = IpUtils.parseHexBinary("860046254000070800007530000003E801010060970769EA05010000000005DC030440C00036EE800036EE80000000003FFE0507000000010000000000000000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        RouterAdvertisement ra = (RouterAdvertisement) payload.message();

        Assert.assertEquals(64, ra.currentHopLimit());
        Assert.assertEquals(0, ra.flags());
        Assert.assertEquals(30000, ra.reachableTime());
        Assert.assertEquals(1000, ra.retransmissionTimer());
        Assert.assertEquals(1800, ra.routerLifetime());
        Assert.assertEquals(3, ra.options().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void neighborSolicitationTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000203AFF3FFE050700000001026097FFFE0769EA3FFE050700000001020086FFFE0580DA");
        byte[] msg = IpUtils.parseHexBinary("8700952D000000003FFE050700000001020086FFFE0580DA01010060970769EA");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        NeighborSolicitation ns = (NeighborSolicitation) payload.message();

        Assert.assertEquals(16, ns.targetAddress().length());
        Assert.assertEquals(1, ns.options().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void neighborAdvertisementTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000183AFF3FFE050700000001020086FFFE0580DA3FFE050700000001026097FFFE0769EA");
        byte[] msg = IpUtils.parseHexBinary("88005688400000003FFE050700000001020086FFFE0580DA");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        NeighborAdvertisement na = (NeighborAdvertisement) payload.message();

        Assert.assertEquals(16, na.targetAddress().length());
        Assert.assertEquals(0, na.options().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void redirectMessageTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000083AFFFE80000000000000020086FFFE0580DAFF020000000000000000000000000002");
        byte[] msg = IpUtils.parseHexBinary("89003107000000000102030405060708010203040506070801020304050607080102030405060708");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        RedirectMessage rm = (RedirectMessage) payload.message();

        Assert.assertEquals(16, rm.targetAddress().length());
        Assert.assertEquals(16, rm.destinationAddress().length());
        Assert.assertEquals(0, rm.options().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }
}
