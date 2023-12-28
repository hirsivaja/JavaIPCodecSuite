package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class ExtensionHeaderTest {
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
