package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import com.github.hirsivaja.ip.ipv6.Ipv6Payload;
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

    @Test
    public void genericIpv4Test() {
        String genericString = "450200180000E000007BDA690000000000000000000000000000000000000000000000000000000000000000";
        byte[] genericBytes = IpUtils.parseHexBinary(genericString);
        IpPayload ipPayload = IpPayload.fromBytes(genericBytes);

        Assert.assertTrue(ipPayload instanceof Ipv4Payload.GenericIpv4Payload);
        
        Ipv4Payload.GenericIpv4Payload genericPayload = (Ipv4Payload.GenericIpv4Payload) ipPayload;

        Assert.assertEquals((byte) 123, genericPayload.header().protocol().type());
    }

    @Test
    public void genericIpv6Test() {
        String genericString = "6000000000187B001234545236234523451123421433453275242334234234234412341232342342000000000000000000000000000000000000000000000000";
        byte[] genericBytes = IpUtils.parseHexBinary(genericString);
        IpPayload ipPayload = IpPayload.fromBytes(genericBytes);

        Assert.assertTrue(ipPayload instanceof Ipv6Payload.GenericIpv6Payload);
        
        Ipv6Payload.GenericIpv6Payload genericPayload = (Ipv6Payload.GenericIpv6Payload) ipPayload;

        Assert.assertEquals((byte) 123, genericPayload.header().nextHeader().type());
    }
}
