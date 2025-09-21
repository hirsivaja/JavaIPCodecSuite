package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class EspPayloadTest {

    @Test
    public void espTest() {
        byte[] espBytes = IpUtils.parseHexBinary("600000000098323F20030051601200000000000000000002200300516012000000000000000000043D713155000000034E727EC9AFF6E017FB5D7398E24ACBCC6560E2B24AEBAA7221C2319E3B7E4BF8CA35C1DC49807F6E2ABA8D1B33E582A390DF754FDF73337E655B25C7907F91A8BF5097ADE5550B7A2D486C7A6CA66EB9B8566F362F0401433A466C59F7C189A1C8258B1EB53A34361915CCAA73EC511504D2940C947AC97A777DC081E2A91CF4F5D0EC4CD041822A20966CD3D39EB280");

        IpPayload payload = IpPayload.decode(ByteBuffer.wrap(espBytes));

        Ipv6Header header = (Ipv6Header) payload.header();
        EspHeader espHeader = (EspHeader) header.extensionHeaders().getFirst();
        Assert.assertEquals(0x3D713155, espHeader.spi());
        Assert.assertEquals(0x00000003, espHeader.seqNumber());
        Assert.assertEquals(144, espHeader.data().length());
        Assert.assertArrayEquals(espBytes, TestUtils.toBytes(payload));
    }

    @Test
    public void espDataTest() {
        byte[] espBytes = IpUtils.parseHexBinary("600000000098323F200300516012000000000000000000022003005160120000000000000000000488772211000001234E727EC9AFF6E017FB5D7398E24ACBCC6560E2B24AEBAA7221C2319E3B7E4BF8CA35C1DC49807F6E2ABA8D1B33E582A390DF754FDF73337E655B25C7907F91A8BF5097ADE5550B7A2D486C7A6CA66EB9B8566F362F0401433A466C59F7C189A1C8258B1EB53A34361915CCAA73EC511504D2940C947AC97A777DC081E2A91CF4F5D0EC4CD041822A2096123A12345678");

        IpPayload payload = IpPayload.decode(ByteBuffer.wrap(espBytes));

        Ipv6Header header = (Ipv6Header) payload.header();
        EspHeader espHeader = (EspHeader) header.extensionHeaders().getFirst();
        Assert.assertEquals(0x88772211, espHeader.spi());
        Assert.assertEquals(0x00000123, espHeader.seqNumber());
        Assert.assertEquals(144, espHeader.data().length());
        Assert.assertArrayEquals(espBytes, TestUtils.toBytes(payload));
    }
}
