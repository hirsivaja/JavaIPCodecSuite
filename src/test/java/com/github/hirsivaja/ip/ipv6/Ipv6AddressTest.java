package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv6AddressTest {
    @Test
    public void addressTest() {
        byte[] ipv6AddressBytes = IpUtils.parseHexBinary("0102030405060708090A0B0C0D0E0F00");
        Ipv6Address address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
        Assert.assertEquals(16, address.length());
        Assert.assertArrayEquals(ipv6AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInet6Address().getAddress());

        ipv6AddressBytes = IpUtils.parseHexBinary("00000000000000000000000000000000");
        address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
        Assert.assertEquals(16, address.length());
        Assert.assertArrayEquals(ipv6AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInet6Address().getAddress());

        ipv6AddressBytes = IpUtils.parseHexBinary("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
        Assert.assertEquals(16, address.length());
        Assert.assertArrayEquals(ipv6AddressBytes, address.rawAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInetAddress().getAddress());
        Assert.assertArrayEquals(ipv6AddressBytes, address.toInet6Address().getAddress());
    }

    @Test
    public void invalidAddressTest() {
        byte[] tooFewBytes = IpUtils.parseHexBinary("01020304");
        ByteBuffer tooFew = ByteBuffer.wrap(tooFewBytes);
        Assert.assertThrows(IllegalArgumentException.class, () -> Ipv6Address.decode(tooFew));
        Assert.assertThrows(IllegalArgumentException.class, () -> new Ipv6Address(tooFewBytes));

        byte[] tooManyBytes = IpUtils.parseHexBinary("0102030405060708090A0B0C0D0E0F0001020304");
        Assert.assertThrows(IllegalArgumentException.class, () -> new Ipv6Address(tooManyBytes));
    }
}
