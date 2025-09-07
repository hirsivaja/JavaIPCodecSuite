package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class NdpOptionTest {

    @Test
    public void mtuOptionTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("0501000001020304");
        NdpOption option = NdpOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof MtuOption);
        MtuOption castOption = (MtuOption) option;
        Assert.assertEquals(0x01020304, castOption.mtu());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void prefixInformationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("03040102030405060708090A000000000F101112131415161718191A1B1C1D1E");
        NdpOption option = NdpOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof PrefixInformationOption);
        PrefixInformationOption castOption = (PrefixInformationOption) option;
        Assert.assertEquals(1, castOption.prefixLen());
        Assert.assertEquals(2, castOption.flags());
        Assert.assertEquals(0x03040506, castOption.validLifetime());
        Assert.assertEquals(0x0708090A, castOption.preferredLifetime());
        Assert.assertEquals(16, castOption.prefix().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void redirectedHeaderTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("04020000000000000102030405060708");
        NdpOption option = NdpOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RedirectedHeaderOption);
        RedirectedHeaderOption castOption = (RedirectedHeaderOption) option;
        Assert.assertEquals(8, castOption.headerAndData().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void sourceLinkLayerTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("0101010203040506");
        NdpOption option = NdpOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof SourceLinkLayerOption);
        SourceLinkLayerOption castOption = (SourceLinkLayerOption) option;
        Assert.assertEquals(6, castOption.linkLayerAddress().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void targetLinkLayerTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("0201010203040506");
        NdpOption option = NdpOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof TargetLinkLayerOption);
        TargetLinkLayerOption castOption = (TargetLinkLayerOption) option;
        Assert.assertEquals(6, castOption.linkLayerAddress().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }
}
