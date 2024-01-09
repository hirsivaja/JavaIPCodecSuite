package com.github.hirsivaja.ip;

import org.junit.Assert;
import org.junit.Test;

public class IpPayloadTest {
    @Test
    public void rplTest() {
        String rplString = "6000000000563A40FE80000000000000020A000A000A000AFF02000000000000000000000000001A9B010DD11EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C";
        byte[] rplBytes = IpUtils.parseHexBinary(rplString);
        IpPayload ipPayload = IpPayload.fromBytes(rplBytes);

        Assert.assertArrayEquals(rplBytes, ipPayload.toBytes());

        IpPayload ipPayloadString = IpPayload.fromByteString(rplString);

        Assert.assertEquals(rplString, ipPayloadString.toByteString());
    }
}
