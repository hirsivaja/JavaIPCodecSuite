package com.github.hirsivaja.ip.icmpv6.rpl.security;

import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class RplSecurityTest {
    @Test
    public void securityTest() {
        byte[] securityBytes = TestUtils.parseHexBinary("0000000012345678FF");
        RplSecurity security = RplSecurity.decode(ByteBuffer.wrap(securityBytes));

        Assert.assertFalse(security.isCounterTypeTime());
        Assert.assertEquals(0, security.getAlgorithm());
        Assert.assertEquals(RplSecurityMode.GROUP_KEY, security.getSecurityMode());
        Assert.assertEquals(RplSecurityLevel.MAC_32, security.getSecurityLevel());
        Assert.assertEquals(0x12345678, security.getCounter());
        Assert.assertFalse(security.getKeyIdentifier().hasKeySource());
        Assert.assertTrue(security.getKeyIdentifier().hasKeyIndex());
        Assert.assertEquals(0, security.getKeyIdentifier().getKeySource());
        Assert.assertEquals((byte) 0xFF, security.getKeyIdentifier().getKeyIndex());

        Assert.assertArrayEquals(securityBytes, TestUtils.toBytes(security));
    }

    @Test
    public void securityTestWithKeySource() {
        byte[] securityBytes = TestUtils.parseHexBinary("0000C300123456781234567812345678FF");
        RplSecurity security = RplSecurity.decode(ByteBuffer.wrap(securityBytes));

        Assert.assertFalse(security.isCounterTypeTime());
        Assert.assertEquals(0, security.getAlgorithm());
        Assert.assertEquals(RplSecurityMode.NODE_SIGNATURE_KEY, security.getSecurityMode());
        Assert.assertEquals(RplSecurityLevel.ENC_SIGN_2048, security.getSecurityLevel());
        Assert.assertEquals(0x12345678, security.getCounter());
        Assert.assertTrue(security.getKeyIdentifier().hasKeySource());
        Assert.assertTrue(security.getKeyIdentifier().hasKeyIndex());
        Assert.assertEquals(0x1234567812345678L, security.getKeyIdentifier().getKeySource());
        Assert.assertEquals((byte) 0xFF, security.getKeyIdentifier().getKeyIndex());

        Assert.assertArrayEquals(securityBytes, TestUtils.toBytes(security));
    }
}
