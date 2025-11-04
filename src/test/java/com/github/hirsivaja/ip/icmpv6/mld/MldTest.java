package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class MldTest {

    @Test
    public void queryV1Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000240001FE800000000000000000000000000001FF0200000000000000000000000000013A00010005020000");
        byte[] msg = IpUtils.parseHexBinary("82003C0303E800000102030405060708090A0B0C0D0E0F00");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        GenericMldMessage query = (GenericMldMessage) payload.message();

        Assert.assertEquals(1000, query.maximumResponseDelay());
        Assert.assertEquals(16, query.multicastAddress().length());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void queryV2Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000240001FE800000000000000000000000000001FF0200000000000000000000000000013A00010005020000");
        byte[] msg = IpUtils.parseHexBinary("820079FF03E8000000000000000000000000000000000000023C0000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        MulticastListenerQueryMessage query = (MulticastListenerQueryMessage) payload.message();

        Assert.assertEquals(1000, query.maximumResponseCode());
        Assert.assertEquals(16, query.multicastAddress().length());
        Assert.assertEquals(2, query.flags());
        Assert.assertEquals(60, query.qqic());
        Assert.assertEquals(0, query.sourceAddresses().size());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }

    @Test
    public void reportV2Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("60000000004C0001FE800000000000007C3BE33937631C08FF0200000000000000000000000000163A00050200000100");
        byte[] msg = IpUtils.parseHexBinary("8F00E0D70000000304000000FF0200000000000000000001FF76BA4204000000FF0200000000000000000000000000FB04000000FF0200000000000000000001FF631C08");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Icmpv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), true, header);
        MulticastListenerReportV2Message report = (MulticastListenerReportV2Message) payload.message();

        Assert.assertEquals(3, report.multicastAccessRecords().size());
        MulticastAccessRecord mar = report.multicastAccessRecords().getFirst();
        Assert.assertEquals(4, mar.recordType());
        Assert.assertEquals(16, mar.multicastAddress().length());
        Assert.assertEquals(0, mar.sourceAddresses().size());
        Assert.assertEquals(0, mar.rawAuxData().length);

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, outBytes);
    }
}
