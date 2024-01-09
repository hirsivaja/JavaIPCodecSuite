package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class MldTest {

    @Test
    public void queryV1Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000240001FE800000000000000000000000000001FF0200000000000000000000000000013A00010005020000");
        byte[] msg = IpUtils.parseHexBinary("82003C0303E800000102030405060708090A0B0C0D0E0F00");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        GenericMldMessage query = (GenericMldMessage) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(1000, query.getMaximumResponseDelay());
        Assert.assertEquals(16, query.getMulticastAddress().getLength());

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 48, outBytes.length));
    }

    @Test
    public void queryV2Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000240001FE800000000000000000000000000001FF0200000000000000000000000000013A00010005020000");
        byte[] msg = IpUtils.parseHexBinary("820079FF03E8000000000000000000000000000000000000023C0000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        MulticastListenerQueryMessage query = (MulticastListenerQueryMessage) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(1000, query.getMaximumResponseCode());
        Assert.assertEquals(16, query.getMulticastAddress().getLength());
        Assert.assertEquals(2, query.getFlags());
        Assert.assertEquals(60, query.getQqic());
        Assert.assertEquals(0, query.getSourceAddresses().length);

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 48, outBytes.length));
    }

    @Test
    public void reportV2Test() {
        byte[] headerBytes = IpUtils.parseHexBinary("60000000004C0001FE800000000000007C3BE33937631C08FF0200000000000000000000000000163A00050200000100");
        byte[] msg = IpUtils.parseHexBinary("8F00E0D70000000304000000FF0200000000000000000001FF76BA4204000000FF0200000000000000000000000000FB04000000FF0200000000000000000001FF631C08");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Payload payload = Icmpv6Payload.decode(ByteBuffer.wrap(msg), header);
        MulticastListenerReportV2Message report = (MulticastListenerReportV2Message) ((Icmpv6Payload) payload).getMessage();

        Assert.assertEquals(3, report.getMulticastAccessRecords().length);
        MulticastAccessRecord record = report.getMulticastAccessRecords()[0];
        Assert.assertEquals(4, record.getRecordType());
        Assert.assertEquals(16, record.getMulticastAddress().getLength());
        Assert.assertEquals(0, record.getSourceAddresses().length);
        Assert.assertEquals(0, record.getAuxData().length);

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 48, outBytes.length));
    }
}
