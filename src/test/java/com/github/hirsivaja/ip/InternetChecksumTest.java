package com.github.hirsivaja.ip;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Enclosed.class)
public class InternetChecksumTest {

    public static class InternetChecksumSingleTest {

        @Test
        public void simpleChecksumTest() {
            String data = "20010DB8000001";
            short expectedChecksum = (short) (0xD146 & 0xFFFF);

            byte[] bytes = IpUtils.parseHexBinary(data);
            short calculatedChecksum = IpUtils.calculateInternetChecksum(bytes);
            System.out.println("calculatedChecksum = " + calculatedChecksum + " (0x" + Integer.toHexString(calculatedChecksum & 0xFFFF).toUpperCase() + ")");
            System.out.println("expectedChecksum = " + expectedChecksum + " (0x" + Integer.toHexString(expectedChecksum & 0xFFFF).toUpperCase() + ")");
            Assert.assertEquals(expectedChecksum, calculatedChecksum);

        }
    }


    @RunWith(Parameterized.class)
    public static class InternetChecksumParamTest {

        private final String testName;
        private final String inputHex;
        private final String fullDataHex;
        private final short expectedChecksum;

        public InternetChecksumParamTest(String testName, String inputHex, String fullDataHex,
                                         short expectedChecksum) {
            this.testName = testName;
            this.inputHex = inputHex;
            this.fullDataHex = fullDataHex;
            this.expectedChecksum = expectedChecksum;
        }

        @Parameterized.Parameters(name = "{0}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][]{
                    {
                            "Basic test",
                            "E34F2396442799F3",
                            "E34F2396442799F31AFF",
                            (short) 0x1AFF,
                    },
                    {
                            "Second basic test",
                            "0001F203F4F5F6F7",
                            "0001F203F4F5F6F7220D",
                            (short) 0x220D
                    },

                    // Multiple carries test cases
                    {
                            "Two 0xFFFF values causing multiple carries",
                            "FFFFFFFF",
                            "FFFFFFFF0000",
                            (short) 0x0000,
                    },
                    {
                            "Pattern causing carry propagation",
                            "FFFF0001",
                            "FFFF0001FFFE",
                            (short) 0xFFFE,
                    },

                    // IPv4 header examples
                    {
                            "IPv4 header with correct checksum should verify to 0",
                            "4500002B50A340007F06C894C0A83801AC1E3DCD",
                            "4500002B50A340007F06C894C0A83801AC1E3DCD",
                            (short) 0x0000,
                    },
                    {
                            "IPv4 header without checksum field",
                            "4500002B50A340007F060000C0A83801AC1E3DCD",
                            "4500002B50A340007F06C894C0A83801AC1E3DCD",
                            (short) 0xC894,
                    },

                    // IPv6 pseudo-header test cases
                    {
                            "IPv6 pseudo-header for ICMPv6",
                            "20010DB8000000000000000000000001" + // Source: 2001:db8::1
                                    "20010DB8000000000000000000000002" + // Dest: 2001:db8::2
                                    "0000000800000000003A",              // Length=8, zeros, next header=58
                            "20010DB8000000000000000000000001" +
                                    "20010DB8000000000000000000000002" +
                                    "0000000800000000003A" + "A448",     // With checksum
                            (short) 0xA448
                    },
                    {
                            "IPv6 pseudo-header with correct checksum should verify to 0",
                            "20010DB8000000000000000000000001" + // Source: 2001:db8::1
                                    "20010DB8000000000000000000000002" + // Dest: 2001:db8::2
                                    "0000000800000000003A" + "A448",     // Length=8, zeros, next header=58, checksum=0xA448
                            "20010DB8000000000000000000000001" +
                                    "20010DB8000000000000000000000002" +
                                    "0000000800000000003A" + "A448",     // With checksum should verify to 0
                            (short) 0x0000,
                    },

                    // Edge cases
                    {
                            "All zeros should produce 0xFFFF checksum",
                            "0000000000000000",
                            "0000000000000000FFFF",
                            (short) 0xFFFF,
                    },
                    {
                            "Single 0xFF byte (odd length)",
                            "FF",
                            "FF0000FF",
                            (short) 0x00FF,
                    }
            });
        }

        @Test
        public void calculateChecksumTest() {
            byte[] data = IpUtils.parseHexBinary(inputHex);
            short actualChecksum = IpUtils.calculateInternetChecksum(data);

            Assert.assertEquals(
                    String.format("Failed for test '%s': expected 0x%04X, got 0x%04X",
                            testName, expectedChecksum & 0xFFFF, actualChecksum & 0xFFFF),
                    expectedChecksum,
                    actualChecksum
            );
        }

        @Test
        public void verifyChecksumTest() {
            byte[] data = IpUtils.parseHexBinary(inputHex);
            short calculatedChecksum = IpUtils.calculateInternetChecksum(data);

            Assert.assertTrue(
                    String.format("Verification failed for test '%s'", testName),
                    IpUtils.verifyInternetChecksum(data, calculatedChecksum)
            );
        }

        @Test
        public void verifyChecksumWithFullDataTest() {
            byte[] fullData = IpUtils.parseHexBinary(fullDataHex);

            Assert.assertTrue(
                    String.format("Full data verification failed for test '%s'", testName),
                    IpUtils.verifyInternetChecksum(fullData)
            );
        }

        @Test
        public void ensureChecksumTest() {
            byte[] data = IpUtils.parseHexBinary(inputHex);
            short calculatedChecksum = IpUtils.calculateInternetChecksum(data);

            try {
                IpUtils.ensureInternetChecksum(data, calculatedChecksum);
            } catch (IllegalArgumentException e) {
                Assert.fail(String.format("ensureInternetChecksum failed for test '%s': %s",
                        testName, e.getMessage()));
            }
        }

        @Test
        public void ensureChecksumWithFullDataTest() {
            byte[] fullData = IpUtils.parseHexBinary(fullDataHex);

            try {
                IpUtils.ensureInternetChecksum(fullData);
            } catch (IllegalArgumentException e) {
                Assert.fail(String.format("ensureInternetChecksum with full data failed for test '%s': %s",
                        testName, e.getMessage()));
            }
        }
    }
}