package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class ExtensionHeaderTest {
    @Test
    public void codecTest() {
        byte[] ipv6Bytes = TestUtils.parseHexBinary("6E00000000240001FE80000000000000021562FFFE6AFEF0FF0200000000000000000000000000163A000502000001008F000D990000000104000000FF020000000000000000000000000002");
        IpPayload payload = Ipv6Payload.decode(ByteBuffer.wrap(ipv6Bytes));

        Assert.assertEquals(1, ((Ipv6Header) payload.getHeader()).getExtensionHeaders().size());
        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void authenticationTest() {
        byte[] ipv6Bytes = TestUtils.parseHexBinary("6E00000000343301FE80000000000000021562FFFE6AFEF0FF020000000000000000000000000016000200001234567887654321555555553A000502000001008F000D990000000104000000FF020000000000000000000000000002");
        IpPayload payload = Ipv6Payload.decode(ByteBuffer.wrap(ipv6Bytes));

        Assert.assertEquals(2, ((Ipv6Header) payload.getHeader()).getExtensionHeaders().size());
        AuthenticationHeaderExtension ah = (AuthenticationHeaderExtension) ((Ipv6Header) payload.getHeader()).getExtensionHeaders().get(0);
        Assert.assertEquals(0x12345678, ah.getAuthenticationHeader().getSpi());
        Assert.assertEquals(0x87654321, ah.getAuthenticationHeader().getSeqNumber());
        Assert.assertArrayEquals(TestUtils.parseHexBinary("55555555"), ah.getAuthenticationHeader().getIcv());
        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void fragmentationTest() {
        byte[] fragmentationBytes = TestUtils.parseHexBinary("3B00111112345678");
        ExtensionHeader header = ExtensionHeader.decode(ByteBuffer.wrap(fragmentationBytes), IpProtocol.FRAGMENTATION);
        Assert.assertTrue(header instanceof FragmentationExtension);
        FragmentationExtension fragmentationHeader = (FragmentationExtension) header;
        Assert.assertEquals(IpProtocol.NO_NEXT, header.getNextHeader());
        Assert.assertEquals(0x0222, fragmentationHeader.getFragmentOffset());
        Assert.assertTrue(fragmentationHeader.isMoreFragments());
        Assert.assertEquals(0x12345678, fragmentationHeader.getIdentification());

        Assert.assertArrayEquals(fragmentationBytes, TestUtils.toBytes(header));
    }
}
