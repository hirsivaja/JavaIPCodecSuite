package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class NdpTest {

    @Test
    public void routerSolicitationTest() {
        byte[] headerBytes = TestUtils.parseHexBinary("6000000000083AFFFE80000000000000020086FFFE0580DAFF020000000000000000000000000002");
        byte[] msg = TestUtils.parseHexBinary("8500755700000000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        RouterSolicitation rs = (RouterSolicitation) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(0, rs.getOptions().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }

    @Test
    public void routerAdvertisementTest() {
        byte[] headerBytes = TestUtils.parseHexBinary("6000000000403AFFFE80000000000000026097FFFE0769EAFF020000000000000000000000000001");
        byte[] msg = TestUtils.parseHexBinary("860046254000070800007530000003E801010060970769EA05010000000005DC030440C00036EE800036EE80000000003FFE0507000000010000000000000000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        RouterAdvertisement ra = (RouterAdvertisement) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(64, ra.getCurrentHopLimit());
        Assert.assertEquals(0, ra.getFlags());
        Assert.assertEquals(30000, ra.getReachableTime());
        Assert.assertEquals(1000, ra.getRetransmissionTimer());
        Assert.assertEquals(1800, ra.getRouterLifetime());
        Assert.assertEquals(3, ra.getOptions().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }

    @Test
    public void neighborSolicitationTest() {
        byte[] headerBytes = TestUtils.parseHexBinary("6000000000203AFF3FFE050700000001026097FFFE0769EA3FFE050700000001020086FFFE0580DA");
        byte[] msg = TestUtils.parseHexBinary("8700952D000000003FFE050700000001020086FFFE0580DA01010060970769EA");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        NeighborSolicitation ns = (NeighborSolicitation) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(16, ns.getTargetAddress().length);
        Assert.assertEquals(1, ns.getOptions().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }

    @Test
    public void neighborAdvertisementTest() {
        byte[] headerBytes = TestUtils.parseHexBinary("6000000000183AFF3FFE050700000001020086FFFE0580DA3FFE050700000001026097FFFE0769EA");
        byte[] msg = TestUtils.parseHexBinary("88005688400000003FFE050700000001020086FFFE0580DA");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        NeighborAdvertisement na = (NeighborAdvertisement) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(16, na.getTargetAddress().length);
        Assert.assertEquals(0, na.getOptions().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }

    @Test
    public void redirectMessageTest() {
        byte[] headerBytes = TestUtils.parseHexBinary("6000000000083AFFFE80000000000000020086FFFE0580DAFF020000000000000000000000000002");
        byte[] msg = TestUtils.parseHexBinary("89003107000000000102030405060708010203040506070801020304050607080102030405060708");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        RedirectMessage rm = (RedirectMessage) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(16, rm.getTargetAddress().length);
        Assert.assertEquals(16, rm.getDestinationAddress().length);
        Assert.assertEquals(0, rm.getOptions().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }
}
