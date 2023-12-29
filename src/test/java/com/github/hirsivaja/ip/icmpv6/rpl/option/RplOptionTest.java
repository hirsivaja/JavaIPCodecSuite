package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class RplOptionTest {
    @Test
    public void padTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("00");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPadOption);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void padNTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("01020000");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPadNOption);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void dagMetricTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("02020000");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplDagMetricContainerOption);
        RplDagMetricContainerOption castOption = (RplDagMetricContainerOption) option;
        Assert.assertEquals(2, castOption.getDagMetricContainerData().length);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void routeInformationTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("0316010201020304000102030405060708090A0B0C0D0E0F");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplRouteInformationOption);
        RplRouteInformationOption castOption = (RplRouteInformationOption) option;
        Assert.assertEquals(1, castOption.getPrefixLen());
        Assert.assertEquals(2, castOption.getPreference());
        Assert.assertEquals(0x01020304, castOption.getRouteLifetime());
        Assert.assertArrayEquals(TestUtils.parseHexBinary("000102030405060708090A0B0C0D0E0F"), castOption.getPrefix());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void dodagConfigurationTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("040E0102030405060708090A000C0D0E");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplDodagConfigurationOption);
        RplDodagConfigurationOption castOption = (RplDodagConfigurationOption) option;
        Assert.assertEquals(1, castOption.getPcs());
        Assert.assertEquals(2, castOption.getDioIntervalMax());
        Assert.assertEquals(3, castOption.getDioIntervalMin());
        Assert.assertEquals(4, castOption.getDioRedundancyConstant());
        Assert.assertEquals(0x0506, castOption.getMaxRankIncrease());
        Assert.assertEquals(0x0708, castOption.getMinHopRankIncrease());
        Assert.assertEquals(0x090A, castOption.getOcp());
        Assert.assertEquals(0x0C, castOption.getDefaultLifetime());
        Assert.assertEquals(0x0D0E, castOption.getLifetimeUnit());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void rplTargetTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("05120102030405060708090A0B0C0D0E0F101112");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTargetOption);
        RplTargetOption castOption = (RplTargetOption) option;
        Assert.assertEquals(1, castOption.getFlags());
        Assert.assertEquals(2, castOption.getPrefixLen());
        Assert.assertEquals(16, castOption.getPrefix().length);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void transitInformationTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("06140102030405060708090A0B0C0D0E0F1011121314");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTransitInformationOption);
        RplTransitInformationOption castOption = (RplTransitInformationOption) option;
        Assert.assertEquals(1, castOption.getFlags());
        Assert.assertEquals(2, castOption.getPathControl());
        Assert.assertEquals(3, castOption.getPathSequence());
        Assert.assertEquals(4, castOption.getPathLifetime());
        Assert.assertEquals(16, castOption.getParentAddress().length);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void solicitedInformationTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("07130102030405060708090A0B0C0D0E0F101112FF");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplSolicitedInformationOption);
        RplSolicitedInformationOption castOption = (RplSolicitedInformationOption) option;
        Assert.assertEquals(1, castOption.getRplInstanceId());
        Assert.assertEquals(2, castOption.getFlags());
        Assert.assertEquals(16, castOption.getDodagId().length);
        Assert.assertEquals((byte) 0xFF, castOption.getVersionNumber());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void prefixInformationTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("081E0102030405060708090A000000000F101112131415161718191A1B1C1D1E");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPrefixInformationOption);
        RplPrefixInformationOption castOption = (RplPrefixInformationOption) option;
        Assert.assertEquals(1, castOption.getPrefixLen());
        Assert.assertEquals(2, castOption.getFlags());
        Assert.assertEquals(0x03040506, castOption.getValidLifetime());
        Assert.assertEquals(0x0708090A, castOption.getPreferredLifetime());
        Assert.assertEquals(16, castOption.getPrefix().length);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void targetDescriptorTest() {
        byte[] optionBytes = TestUtils.parseHexBinary("090412345678");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTargetDescriptorOption);
        RplTargetDescriptorOption castOption = (RplTargetDescriptorOption) option;
        Assert.assertEquals(0x12345678, castOption.getDescriptor());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }
}
