package com.github.hirsivaja.ip.udp;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class UdpPayloadTest {

    @Test
    public void udpTest() {
        byte[] ipv4HeaderBytes = IpUtils.parseHexBinary("45C0003E000000000111CEEB0A000002E0000002");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] udpBytes = IpUtils.parseHexBinary("02860286002A60E10001001E0AC8C8660000010000140000000004000004000F0000040100040AC8C866");
        UdpMessagePayload payload = (UdpMessagePayload) UdpMessagePayload.decode(ByteBuffer.wrap(udpBytes), ipv4Header);

        UdpHeader udpHeader = payload.getUdpHeader();
        Assert.assertEquals(646, udpHeader.getSrcPort());
        Assert.assertEquals(646, udpHeader.getDstPort());
        Assert.assertEquals(34, payload.getPayload().length);

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(udpBytes, Arrays.copyOfRange(outBytes, 20, outBytes.length));
    }
}
