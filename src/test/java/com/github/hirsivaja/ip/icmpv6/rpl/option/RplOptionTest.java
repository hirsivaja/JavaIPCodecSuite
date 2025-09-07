package com.github.hirsivaja.ip.icmpv6.rpl.option;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class RplOptionTest {
    @Test
    public void padTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("00");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPadOption);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void padNTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("01020000");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPadNOption);

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void dagMetricTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("02020000");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplDagMetricContainerOption);
        RplDagMetricContainerOption castOption = (RplDagMetricContainerOption) option;
        Assert.assertEquals(2, castOption.dagMetricContainerData().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void routeInformationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("0316010201020304000102030405060708090A0B0C0D0E0F");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplRouteInformationOption);
        RplRouteInformationOption castOption = (RplRouteInformationOption) option;
        Assert.assertEquals(1, castOption.prefixLen());
        Assert.assertEquals(2, castOption.preference());
        Assert.assertEquals(0x01020304, castOption.routeLifetime());
        Assert.assertArrayEquals(IpUtils.parseHexBinary("000102030405060708090A0B0C0D0E0F"), castOption.rawPrefix());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void dodagConfigurationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("040E0102030405060708090A000C0D0E");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplDodagConfigurationOption);
        RplDodagConfigurationOption castOption = (RplDodagConfigurationOption) option;
        Assert.assertEquals(1, castOption.pcs());
        Assert.assertEquals(2, castOption.dioIntervalMax());
        Assert.assertEquals(3, castOption.dioIntervalMin());
        Assert.assertEquals(4, castOption.dioRedundancyConstant());
        Assert.assertEquals(0x0506, castOption.maxRankIncrease());
        Assert.assertEquals(0x0708, castOption.minHopRankIncrease());
        Assert.assertEquals(0x090A, castOption.ocp());
        Assert.assertEquals(0x0C, castOption.defaultLifetime());
        Assert.assertEquals(0x0D0E, castOption.lifetimeUnit());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void rplTargetTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("05120102030405060708090A0B0C0D0E0F101112");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTargetOption);
        RplTargetOption castOption = (RplTargetOption) option;
        Assert.assertEquals(1, castOption.flags());
        Assert.assertEquals(2, castOption.prefixLen());
        Assert.assertEquals(16, castOption.prefix().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void transitInformationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("06140102030405060708090A0B0C0D0E0F1011121314");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTransitInformationOption);
        RplTransitInformationOption castOption = (RplTransitInformationOption) option;
        Assert.assertEquals(1, castOption.flags());
        Assert.assertEquals(2, castOption.pathControl());
        Assert.assertEquals(3, castOption.pathSequence());
        Assert.assertEquals(4, castOption.pathLifetime());
        Assert.assertEquals(16, castOption.parentAddress().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));

        byte[] optionWithoutParentAddressBytes = IpUtils.parseHexBinary("060401020304");
        RplOption optionWithoutParent = RplOption.decode(ByteBuffer.wrap(optionWithoutParentAddressBytes));

        Assert.assertTrue(optionWithoutParent instanceof RplTransitInformationOption);
        RplTransitInformationOption withoutParent = (RplTransitInformationOption) optionWithoutParent;
        Assert.assertEquals(1, withoutParent.flags());
        Assert.assertEquals(2, withoutParent.pathControl());
        Assert.assertEquals(3, withoutParent.pathSequence());
        Assert.assertEquals(4, withoutParent.pathLifetime());
        Assert.assertNull(withoutParent.parentAddress());

        Assert.assertArrayEquals(optionWithoutParentAddressBytes, TestUtils.toBytes(optionWithoutParent));
    }

    @Test
    public void solicitedInformationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("07130102030405060708090A0B0C0D0E0F101112FF");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplSolicitedInformationOption);
        RplSolicitedInformationOption castOption = (RplSolicitedInformationOption) option;
        Assert.assertEquals(1, castOption.rplInstanceId());
        Assert.assertEquals(2, castOption.flags());
        Assert.assertEquals(16, castOption.dodagId().length());
        Assert.assertEquals((byte) 0xFF, castOption.versionNumber());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void prefixInformationTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("081E0102030405060708090A000000000F101112131415161718191A1B1C1D1E");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplPrefixInformationOption);
        RplPrefixInformationOption castOption = (RplPrefixInformationOption) option;
        Assert.assertEquals(1, castOption.prefixLen());
        Assert.assertEquals(2, castOption.flags());
        Assert.assertEquals(0x03040506, castOption.validLifetime());
        Assert.assertEquals(0x0708090A, castOption.preferredLifetime());
        Assert.assertEquals(16, castOption.prefix().length());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }

    @Test
    public void targetDescriptorTest() {
        byte[] optionBytes = IpUtils.parseHexBinary("090412345678");
        RplOption option = RplOption.decode(ByteBuffer.wrap(optionBytes));

        Assert.assertTrue(option instanceof RplTargetDescriptorOption);
        RplTargetDescriptorOption castOption = (RplTargetDescriptorOption) option;
        Assert.assertEquals(0x12345678, castOption.descriptor());

        Assert.assertArrayEquals(optionBytes, TestUtils.toBytes(option));
    }
}
