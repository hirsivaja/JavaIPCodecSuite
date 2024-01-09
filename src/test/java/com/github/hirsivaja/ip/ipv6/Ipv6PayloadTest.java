package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv6PayloadTest {
    @Test
    public void codecTest() {
        byte[] ipv6Bytes = IpUtils.parseHexBinary("60000000001411043FFE050700000001020086FFFE0580DA3FFE05010410000002C0DFFFFE47033EA07582A40014CF470A040000F9C8E7369D250B00");
        IpPayload payload = Ipv6Payload.decode(ByteBuffer.wrap(ipv6Bytes));

        Assert.assertTrue(Ipv6Payload.isIpv6Payload(ByteBuffer.wrap(ipv6Bytes)));
        Assert.assertArrayEquals(ipv6Bytes, TestUtils.toBytes(payload));
    }
}
