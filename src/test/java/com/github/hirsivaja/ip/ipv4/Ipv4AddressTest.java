package com.github.hirsivaja.ip.ipv4;

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
public class Ipv4AddressTest {

    public static class Ipv4AddressSingleTest {
        @Test
        public void addressTest() {
            byte[] ipv4AddressBytes = IpUtils.parseHexBinary("01020304");
            Ipv4Address address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
            Assert.assertEquals(4, address.getLength());
            Assert.assertArrayEquals(ipv4AddressBytes, address.getAddress());
            Assert.assertArrayEquals(ipv4AddressBytes, address.toInetAddress().getAddress());
            Assert.assertArrayEquals(ipv4AddressBytes, address.toInet4Address().getAddress());

            ipv4AddressBytes = IpUtils.parseHexBinary("00000000");
            address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
            Assert.assertEquals(4, address.getLength());
            Assert.assertArrayEquals(ipv4AddressBytes, address.getAddress());
            Assert.assertArrayEquals(ipv4AddressBytes, address.toInetAddress().getAddress());
            Assert.assertArrayEquals(ipv4AddressBytes, address.toInet4Address().getAddress());

            ipv4AddressBytes = IpUtils.parseHexBinary("FFFFFFFF");
            address = Ipv4Address.decode(ByteBuffer.wrap(ipv4AddressBytes));
            Assert.assertEquals(4, address.getLength());
            Assert.assertArrayEquals(ipv4AddressBytes, address.getAddress());
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

    @RunWith(Parameterized.class)
    public static class Ipv4AddressParameterizedTest {

        private final String description;
        private final byte[] input;
        private final String expected;

        public Ipv4AddressParameterizedTest(String description, byte[] input, String expected) {
            this.description = description;
            this.input = input;
            this.expected = expected;
        }

        @Parameters(name = "{0}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    // Basic edge cases
                    {"All zeros",
                            new byte[]{0, 0, 0, 0},
                            "0.0.0.0"},

                    {"All ones (broadcast)",
                            new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255},
                            "255.255.255.255"},

                    {"Loopback address",
                            new byte[]{127, 0, 0, 1},
                            "127.0.0.1"},

                    // Private network addresses
                    {"Private network - Class A",
                            new byte[]{10, 0, 0, 1},
                            "10.0.0.1"},

                    {"Private network - Class B",
                            new byte[]{(byte) 172, 16, 0, 1},
                            "172.16.0.1"},

                    {"Private network - Class C",
                            new byte[]{(byte) 192, (byte) 168, 1, 1},
                            "192.168.1.1"},

                    // Documentation addresses (RFC 5737)
                    {"Documentation prefix (TEST-NET-1)",
                            new byte[]{(byte) 192, 0, 2, 1},
                            "192.0.2.1"},

                    {"Documentation prefix (TEST-NET-2)",
                            new byte[]{(byte) 198, 51, 100, 1},
                            "198.51.100.1"},

                    {"Documentation prefix (TEST-NET-3)",
                            new byte[]{(byte) 203, 0, 113, 1},
                            "203.0.113.1"},

                    // Special purpose addresses

                    {"Multicast address",
                            new byte[]{(byte) 224, 0, 0, 1},
                            "224.0.0.1"},

                    {"Limited broadcast",
                            new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255},
                            "255.255.255.255"},

                    // Class boundaries
                    {"Class A maximum",
                            new byte[]{127, (byte) 255, (byte) 255, (byte) 254},
                            "127.255.255.254"},

                    {"Class B start",
                            new byte[]{(byte) 128, 0, 0, 1},
                            "128.0.0.1"},

                    {"Class C start",
                            new byte[]{(byte) 192, 0, 0, 1},
                            "192.0.0.1"},

                    // Test signed byte handling (values 128-255)
                    {"High value octets",
                            new byte[]{(byte) 255, 0, (byte) 255, 0},
                            "255.0.255.0"},

                    {"Mixed high and low values",
                            new byte[]{(byte) 203, 0, 113, (byte) 195},
                            "203.0.113.195"},

                    {"All high values",
                            new byte[]{(byte) 240, (byte) 248, (byte) 252, (byte) 254},
                            "240.248.252.254"},

                    {"Common gateway",
                            new byte[]{(byte) 192, (byte) 168, 1, (byte) 254},
                            "192.168.1.254"},

                    {"Common router",
                            new byte[]{(byte) 192, (byte) 168, 0, 1},
                            "192.168.0.1"},

                    // Sequential and pattern testing
                    {"Sequential values",
                            new byte[]{1, 2, 3, 4},
                            "1.2.3.4"},

                    {"Power of 2 values",
                            new byte[]{1, 2, 4, 8},
                            "1.2.4.8"},

                    {"128 values (MSB set)",
                            new byte[]{(byte) 128, (byte) 128, (byte) 128, (byte) 128},
                            "128.128.128.128"},

                    {"Alternating pattern",
                            new byte[]{(byte) 170, 85, (byte) 170, 85},
                            "170.85.170.85"},

                    // Leading zero suppression test cases
                    {"Single digits",
                            new byte[]{1, 2, 3, 4},
                            "1.2.3.4"},

                    {"Mixed digit counts",
                            new byte[]{10, 100, 1, (byte) 200},
                            "10.100.1.200"},

                    {"No leading zeros",
                            new byte[]{123, 45, 67, 89},
                            "123.45.67.89"}
            });
        }

        @Test
        public void ipv4AddressToStringTest() {
            Ipv4Address addr = new Ipv4Address(input);
            assertEquals("Decimal conversion failed for: " + description,
                    expected, addr.toString());
        }
    }
}