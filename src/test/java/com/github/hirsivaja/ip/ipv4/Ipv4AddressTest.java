package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv4AddressTest {
    @Test
    public void addressTest() {
        byte[] ipv4AddressBytes = IpUtils.parseHexBinary("01020304");
        Ipv4Address address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
        Assert.assertEquals(4, address.length());
        Assert.assertArrayEquals(ipv4AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInet4Address().getAddress());

        ipv4AddressBytes = IpUtils.parseHexBinary("00000000");
        address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
        Assert.assertEquals(4, address.length());
        Assert.assertArrayEquals(ipv4AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInet4Address().getAddress());

        ipv4AddressBytes = IpUtils.parseHexBinary("FFFFFFFF");
        address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
        Assert.assertEquals(4, address.length());
        Assert.assertArrayEquals(ipv4AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv4AddressBytes, address.toInet4Address().getAddress());
    }

    @Test
    public void invalidAddressTest() {
        byte[] tooFewBytes = IpUtils.parseHexBinary("010203");
        ByteBuffer tooFew = ByteBuffer.wrap(tooFewBytes);
        Assert.assertThrows(IllegalArgumentException.class, () -> Ipv4Address.decode(tooFew));
        Assert.assertThrows(IllegalArgumentException.class, () -> new Ipv4Address(tooFewBytes));

        byte[] tooManyBytes = IpUtils.parseHexBinary("0102030405");
        Assert.assertThrows(IllegalArgumentException.class, () -> new Ipv4Address(tooManyBytes));
    }
}
