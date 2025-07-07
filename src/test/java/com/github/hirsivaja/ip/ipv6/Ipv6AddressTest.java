package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Enclosed.class)
public class Ipv6AddressTest {

    public static class Ipv6AddressSingleTest {
        @Test
        public void addressTest() {
            byte[] ipv6AddressBytes = IpUtils.parseHexBinary("0102030405060708090A0B0C0D0E0F00");
            Ipv6Address address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
            Assert.assertEquals(16, address.getLength());
            Assert.assertArrayEquals(ipv6AddressBytes, address.getAddress());
            Assert.assertArrayEquals(ipv6AddressBytes, address.toInetAddress().getAddress());
            Assert.assertArrayEquals(ipv6AddressBytes, address.toInet6Address().getAddress());

            ipv6AddressBytes = IpUtils.parseHexBinary("00000000000000000000000000000000");
            address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
            Assert.assertEquals(16, address.getLength());
            Assert.assertArrayEquals(ipv6AddressBytes, address.getAddress());
            Assert.assertArrayEquals(ipv6AddressBytes, address.toInetAddress().getAddress());
            Assert.assertArrayEquals(ipv6AddressBytes, address.toInet6Address().getAddress());

            ipv6AddressBytes = IpUtils.parseHexBinary("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
            address = Ipv6Address.decode(ByteBuffer.wrap(ipv6AddressBytes));
            Assert.assertEquals(16, address.getLength());
            Assert.assertArrayEquals(ipv6AddressBytes, address.getAddress());
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

    @RunWith(Parameterized.class)
    public static class Ipv6AddressParameterizedTest {

        private final String description;
        private final byte[] input;
        private final String expectedCompressed;
        private final String expectedFull;

        public Ipv6AddressParameterizedTest(String description, byte[] input,
                                            String expectedCompressed, String expectedFull) {
            this.description = description;
            this.input = input;
            this.expectedCompressed = expectedCompressed;
            this.expectedFull = expectedFull;
        }

        @Parameters(name = "{0}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    // Basic edge cases
                    {"All zeros",
                            new byte[16],
                            "::",
                            "0000:0000:0000:0000:0000:0000:0000:0000"},

                    {"Loopback address",
                            new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                            "::1",
                            "0000:0000:0000:0000:0000:0000:0000:0001"},

                    // No compression scenarios
                    {"No compression needed - no consecutive zeros",
                            new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
                                    0x00, 0x05, 0x00, 0x06},
                            "2001:db8:1:2:3:4:5:6",
                            "2001:0db8:0001:0002:0003:0004:0005:0006"},

                    {"Single zero groups should not be compressed",
                            new byte[]{0x20, 0x01, 0x00, 0x00, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                                    0x00, 0x02, 0x00, 0x03},
                            "2001:0:db8:0:1:0:2:3",
                            "2001:0000:0db8:0000:0001:0000:0002:0003"},

                    // Zero sequences at different positions
                    {"Zeros at the beginning",
                            new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
                                    0x03, 0x00, 0x04},
                            "::1:2:3:4",
                            "0000:0000:0000:0000:0001:0002:0003:0004"},

                    {"Zeros at the end",
                            new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00},
                            "2001:db8::",
                            "2001:0db8:0000:0000:0000:0000:0000:0000"},

                    {"Zeros in the middle",
                            new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x01},
                            "2001:db8::1",
                            "2001:0db8:0000:0000:0000:0000:0000:0001"},

                    // Multiple zero sequences
                    {"Multiple zero sequences - compress longest",
                            new byte[]{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x01},
                            "2001:0:0:db8::1",
                            "2001:0000:0000:0db8:0000:0000:0000:0001"},

                    {"Equal length zero sequences - compress first occurrence",
                            new byte[]{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x01, 0x00, 0x02},
                            "2001::db8:0:0:1:2",
                            "2001:0000:0000:0db8:0000:0000:0001:0002"},

                    {"Exactly two consecutive zeros",
                            new byte[]{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, (byte) 0xb8, 0x00, 0x01, 0x00, 0x02,
                                    0x00, 0x03, 0x00, 0x04},
                            "2001::db8:1:2:3:4",
                            "2001:0000:0000:0db8:0001:0002:0003:0004"},

                    // Formatting tests
                    {"Maximum values in groups",
                            new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                    (byte) 0xFF, (byte) 0xFF,
                                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                    (byte) 0xFF, (byte) 0xFF},
                            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},

                    {"Mixed case should be lowercase",
                            new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12, 0x34, 0x56, 0x78, (byte) 0x9A,
                                    (byte) 0xBC, (byte) 0xDE, (byte) 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55},
                            "abcd:ef12:3456:789a:bcde:f011:2233:4455",
                            "abcd:ef12:3456:789a:bcde:f011:2233:4455"},

                    {"Leading zeros should be omitted in compressed format",
                            new byte[]{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
                                    0x07, 0x00, 0x08},
                            "1:2:3:4:5:6:7:8",
                            "0001:0002:0003:0004:0005:0006:0007:0008"},

                    // Real-world address types
                    {"Link-local prefix",
                            new byte[]{(byte) 0xfe, (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                            "fe80::1",
                            "fe80:0000:0000:0000:0000:0000:0000:0001"},

                    {"Documentation prefix",
                            new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                            "2001:db8::1",
                            "2001:0db8:0000:0000:0000:0000:0000:0001"},

                    {"Multicast prefix",
                            new byte[]{(byte) 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                            "ff02::1",
                            "ff02:0000:0000:0000:0000:0000:0000:0001"},

                    // Edge cases for zero sequence detection
                    {"Alternating single zeros",
                            new byte[]{0x20, 0x01, 0x00, 0x00, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00,
                                    0x56, 0x78, 0x00, 0x00},
                            "2001:0:db8:0:1234:0:5678:0",
                            "2001:0000:0db8:0000:1234:0000:5678:0000"},

                    {"Three zero groups at start",
                            new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x01,
                                    0x00, 0x02, 0x00, 0x03},
                            "::2001:db8:1:2:3",
                            "0000:0000:0000:2001:0db8:0001:0002:0003"},

                    {"Three zero groups at end",
                            new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00},
                            "2001:db8:1::",
                            "2001:0db8:0001:0000:0000:0000:0000:0000"},

                    {"All groups have leading zeros",
                            new byte[]{0x00, 0x12, 0x00, 0x34, 0x00, 0x56, 0x00, 0x78, 0x00, (byte) 0x9a, 0x00,
                                    (byte) 0xbc, 0x00, (byte) 0xde, 0x00, (byte) 0xf0},
                            "12:34:56:78:9a:bc:de:f0",
                            "0012:0034:0056:0078:009a:00bc:00de:00f0"}
            });
        }

        @Test
        public void ipv6AddressToStringTest() {
            Ipv6Address addr = new Ipv6Address(input);
            assertEquals("Compressed format failed for: " + description,
                    expectedCompressed, addr.toCompressedString());
            assertEquals("Full format failed for: " + description,
                    expectedFull, addr.toFullString());
            assertEquals("toString() should return compressed format for: " + description,
                    expectedCompressed, addr.toString());
        }
    }

}
