package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.*;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Payload;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastAccessRecord;
import com.github.hirsivaja.ip.icmpv6.mld.MulticastListenerReportV2Message;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
import com.github.hirsivaja.ip.ipv6.extension.destination.DestinationOptionType;
import com.github.hirsivaja.ip.ipv6.extension.destination.GenericDestinationOption;
import com.github.hirsivaja.ip.ipv6.extension.mobility.MobilityMessageType;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.List;

public class ExtensionHeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv6Bytes = IpUtils.parseHexBinary("6E00000000240001FE80000000000000021562FFFE6AFEF0FF0200000000000000000000000000163A000502000001008F000D990000000104000000FF020000000000000000000000000002");
        IpPayload payload = Ipv6Payload.decode(ByteBuffer.wrap(ipv6Bytes));

        Assert.assertEquals(1, ((Ipv6Header) payload.header()).extensionHeaders().size());
        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void createTest() {
        byte[] ipv6Bytes = IpUtils.parseHexBinary("6E00000000240001FE80000000000000021562FFFE6AFEF0FF0200000000000000000000000000163A000502000001008F000D990000000104000000FF020000000000000000000000000002");

        Icmpv6Message message = new MulticastListenerReportV2Message(List.of(new MulticastAccessRecord((byte) 4, new Ipv6Address(IpUtils.parseHexBinary("FF020000000000000000000000000002")), List.of(), new byte[0])));
        List<ExtensionHeader> extensionHeaders = List.of(new HopByHopExtension(IpProtocols.ICMPV6, List.of(new GenericDestinationOption(DestinationOptionType.ROUTER_ALERT, new byte[]{0, 0}), new GenericDestinationOption(DestinationOptionType.PAD_N, new byte[]{}))));
        Ipv6Header header = new Ipv6Header((byte) 0xF8, EcnCodePoint.NO_ECN_NO_ECT, 0, (short) (message.length() + Ipv6Header.calculateExtensionsLength(extensionHeaders)), IpProtocols.HOP_BY_HOP, (byte) 1, new Ipv6Address(IpUtils.parseHexBinary("FE80000000000000021562FFFE6AFEF0")), new Ipv6Address(IpUtils.parseHexBinary("FF020000000000000000000000000016")), extensionHeaders);
        IpPayload payload = new Icmpv6Payload(header, message);

        Assert.assertEquals(1, ((Ipv6Header) payload.header()).extensionHeaders().size());
        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void authenticationTest() {
        byte[] ipv6Bytes = IpUtils.parseHexBinary("6E00000000343301FE80000000000000021562FFFE6AFEF0FF020000000000000000000000000016000200001234567887654321555555553A000502000001008F000D990000000104000000FF020000000000000000000000000002");
        IpPayload payload = Ipv6Payload.decode(ByteBuffer.wrap(ipv6Bytes));

        Assert.assertEquals(2, ((Ipv6Header) payload.header()).extensionHeaders().size());
        AuthenticationHeaderExtension ah = (AuthenticationHeaderExtension) ((Ipv6Header) payload.header()).extensionHeaders().getFirst();
        Assert.assertEquals(0x12345678, ah.authenticationHeader().spi());
        Assert.assertEquals(0x87654321, ah.authenticationHeader().seqNumber());
        Assert.assertArrayEquals(IpUtils.parseHexBinary("55555555"), ah.authenticationHeader().icv().array());
        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void fragmentationTest() {
        byte[] fragmentationBytes = IpUtils.parseHexBinary("3B00111112345678");
        ExtensionHeader header = ExtensionHeader.decode(ByteBuffer.wrap(fragmentationBytes), IpProtocols.IPV6_FRAGMENTATION);
        Assert.assertTrue(header instanceof FragmentationExtension);
        FragmentationExtension fragmentationHeader = (FragmentationExtension) header;
        Assert.assertEquals(IpProtocols.IPV6_NO_NEXT, header.nextHeader());
        Assert.assertEquals(0x0222, fragmentationHeader.fragmentOffset());
        Assert.assertTrue(fragmentationHeader.isMoreFragments());
        Assert.assertEquals(0x12345678, fragmentationHeader.identification());

        Assert.assertArrayEquals(fragmentationBytes, TestUtils.toBytes(header));
    }

    @Test
    public void mobilityTest() {
        byte[] mobilityBytes = IpUtils.parseHexBinary("3B010100123400000123456789ABCDEF");
        ExtensionHeader header = ExtensionHeader.decode(ByteBuffer.wrap(mobilityBytes), IpProtocols.MOBILITY_HEADER);

        Assert.assertTrue(header instanceof MobilityHeaderExtension);
        MobilityHeaderExtension mobilityHeader = (MobilityHeaderExtension) header;
        Assert.assertEquals(IpProtocols.IPV6_NO_NEXT, header.nextHeader());
        Assert.assertEquals(MobilityMessageType.HOME_TEST_INIT, mobilityHeader.mobilityMessage().type());

        Assert.assertArrayEquals(mobilityBytes, TestUtils.toBytes(header));
    }

    @Test
    public void mobilityBindingUpdateTest() {
        byte[] mobilityBytes = IpUtils.parseHexBinary("3B010500123412344321567800000000");
        ExtensionHeader header = ExtensionHeader.decode(ByteBuffer.wrap(mobilityBytes), IpProtocols.MOBILITY_HEADER);

        Assert.assertTrue(header instanceof MobilityHeaderExtension);
        MobilityHeaderExtension mobilityHeader = (MobilityHeaderExtension) header;
        Assert.assertEquals(IpProtocols.IPV6_NO_NEXT, header.nextHeader());
        Assert.assertEquals(MobilityMessageType.BINDING_UPDATE, mobilityHeader.mobilityMessage().type());

        Assert.assertArrayEquals(mobilityBytes, TestUtils.toBytes(header));
    }
}
