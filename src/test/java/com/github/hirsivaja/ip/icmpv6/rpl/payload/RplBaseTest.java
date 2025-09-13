package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.rpl.RplControlMessage;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurityMode;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class RplBaseTest {
    @Test
    public void disTest() {
        byte[] disBytes = IpUtils.parseHexBinary("000000000000");
        RplControlMessage rplPayload = RplControlMessage.fromByteArray(disBytes, Icmpv6Codes.DIS);

        Assert.assertTrue(rplPayload.base() instanceof RplDis);
        Assert.assertFalse(rplPayload.hasSecurity());
        Assert.assertEquals(4, rplPayload.options().size());

        Assert.assertArrayEquals(disBytes, rplPayload.toByteArray());

        RplDis dis = new RplDis();
        Assert.assertEquals(Icmpv6Codes.DIS, dis.code(false));
    }

    @Test
    public void dioTest() {
        byte[] dioBytes = IpUtils.parseHexBinary("1EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C");
        RplControlMessage rplPayload = (RplControlMessage) RplControlMessage.decode(ByteBuffer.wrap(dioBytes), Icmpv6Codes.DIO);

        RplDio dio = (RplDio) rplPayload.base();
        Assert.assertEquals(30, dio.rplInstance());
        Assert.assertEquals(-15, dio.versionNumber());
        Assert.assertEquals(768, dio.rank());
        Assert.assertEquals(8, dio.flags());
        Assert.assertEquals((byte) 0xF0, dio.dtsn());
        Assert.assertEquals(16, dio.dodagid().length());
        Assert.assertEquals(3, rplPayload.options().size());

        Assert.assertArrayEquals(dioBytes, rplPayload.toByteArray());
    }

    @Test
    public void daoTest() {
        byte[] daoBytes = IpUtils.parseHexBinary("01C0000405060708090A0B0C0D0E0F1011121314");
        RplControlMessage rplPayload = (RplControlMessage) RplControlMessage.decode(ByteBuffer.wrap(daoBytes), Icmpv6Codes.DAO);

        RplDao dao = (RplDao) rplPayload.base();
        Assert.assertEquals(1, dao.rplInstance());
        Assert.assertEquals((byte) 0xC0, dao.flags());
        Assert.assertEquals(4, dao.daoSequence());
        Assert.assertEquals(16, dao.dodagid().length());
        Assert.assertEquals(0, rplPayload.options().size());

        Assert.assertArrayEquals(daoBytes, rplPayload.toByteArray());

        RplDao dao2 = new RplDao((byte) 0x12, (byte) 0xC0, (byte) 0xF1, null);
        Assert.assertEquals(0x12, dao2.rplInstance());
        Assert.assertEquals((byte) 0xC0, dao2.flags());
        Assert.assertEquals((byte) 0xF1, dao2.daoSequence());
        Assert.assertNull(dao2.dodagid());
    }

    @Test
    public void daoAckTest() {
        byte[] daoAckBytes = IpUtils.parseHexBinary("0180030405060708090A0B0C0D0E0F1011121314");
        RplControlMessage rplPayload = (RplControlMessage) RplControlMessage.decode(ByteBuffer.wrap(daoAckBytes), Icmpv6Codes.DAO_ACK);

        RplDaoAck daoAck = (RplDaoAck) rplPayload.base();
        Assert.assertEquals(1, daoAck.rplInstance());
        Assert.assertEquals((byte) 0x80, daoAck.flags());
        Assert.assertEquals(3, daoAck.daoSequence());
        Assert.assertEquals(4, daoAck.status());
        Assert.assertEquals(16, daoAck.dodagid().length());
        Assert.assertEquals(0, rplPayload.options().size());

        Assert.assertArrayEquals(daoAckBytes, rplPayload.toByteArray());
    }

    @Test
    public void ccTest() {
        byte[] ccBytes = IpUtils.parseHexBinary("0000000012345678FF008044441234567812345678123456781234567812345678");
        RplControlMessage rplPayload = (RplControlMessage) RplControlMessage.decode(ByteBuffer.wrap(ccBytes), Icmpv6Codes.CONSISTENCY_CHECK);

        RplConsistencyCheck cc = (RplConsistencyCheck) rplPayload.base();
        Assert.assertTrue(rplPayload.hasSecurity());
        Assert.assertEquals(RplSecurityMode.GROUP_KEY, rplPayload.security().securityMode());
        Assert.assertEquals(0, cc.rplInstance());
        Assert.assertEquals((byte) 0x80, cc.flags());
        Assert.assertEquals((short) 0x4444, cc.ccNonce());
        Assert.assertEquals(16, cc.dodagid().length());
        Assert.assertEquals(0x12345678, cc.destinationCounter());
        Assert.assertEquals(0, rplPayload.options().size());

        Assert.assertArrayEquals(ccBytes, rplPayload.toByteArray());
    }
}
