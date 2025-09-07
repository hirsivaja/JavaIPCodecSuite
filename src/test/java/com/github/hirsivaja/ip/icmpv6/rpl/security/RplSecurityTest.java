package com.github.hirsivaja.ip.icmpv6.rpl.security;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class RplSecurityTest {
    @Test
    public void securityTest() {
        byte[] securityBytes = IpUtils.parseHexBinary("0000000012345678FF");
        RplSecurity security = RplSecurity.decode(ByteBuffer.wrap(securityBytes));

        Assert.assertFalse(security.isCounterTypeTime());
        Assert.assertEquals(0, security.algorithm());
        Assert.assertEquals(RplSecurityMode.GROUP_KEY, security.securityMode());
        Assert.assertEquals(RplSecurityLevel.MAC_32, security.securityLevel());
        Assert.assertEquals(0x12345678, security.counter());
        Assert.assertFalse(security.keyIdentifier().hasKeySource());
        Assert.assertTrue(security.keyIdentifier().hasKeyIndex());
        Assert.assertEquals(0, security.keyIdentifier().keySource());
        Assert.assertEquals((byte) 0xFF, security.keyIdentifier().keyIndex());

        Assert.assertArrayEquals(securityBytes, TestUtils.toBytes(security));
    }

    @Test
    public void securityTestWithKeySource() {
        byte[] securityBytes = IpUtils.parseHexBinary("0000C300123456781234567812345678FF");
        RplSecurity security = RplSecurity.decode(ByteBuffer.wrap(securityBytes));

        Assert.assertFalse(security.isCounterTypeTime());
        Assert.assertEquals(0, security.algorithm());
        Assert.assertEquals(RplSecurityMode.NODE_SIGNATURE_KEY, security.securityMode());
        Assert.assertEquals(RplSecurityLevel.ENC_SIGN_2048, security.securityLevel());
        Assert.assertEquals(0x12345678, security.counter());
        Assert.assertTrue(security.keyIdentifier().hasKeySource());
        Assert.assertTrue(security.keyIdentifier().hasKeyIndex());
        Assert.assertEquals(0x1234567812345678L, security.keyIdentifier().keySource());
        Assert.assertEquals((byte) 0xFF, security.keyIdentifier().keyIndex());

        Assert.assertArrayEquals(securityBytes, TestUtils.toBytes(security));
    }
}
