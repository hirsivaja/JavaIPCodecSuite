package com.github.hirsivaja.ip.icmpv6.rpl.payload;

import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurityMode;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class RplPayloadTest {
    @Test
    public void disTest() {
        byte[] disBytes = TestUtils.parseHexBinary("000000000000");
        RplPayload rplPayload = RplPayload.fromByteArray(disBytes, RplPayloadType.DIS);

        Assert.assertTrue(rplPayload instanceof RplDis);
        Assert.assertFalse(rplPayload.hasSecurity());
        Assert.assertEquals(4, rplPayload.getOptions().size());

        Assert.assertArrayEquals(disBytes, rplPayload.toByteArray());

        RplDis dis = new RplDis(new ArrayList<>());
        Assert.assertEquals(0, dis.getOptions().size());
    }

    @Test
    public void dioTest() {
        byte[] dioBytes = TestUtils.parseHexBinary("1EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C");
        RplDio dio = RplDio.decode(ByteBuffer.wrap(dioBytes), false);

        Assert.assertEquals(30, dio.getRplInstance());
        Assert.assertEquals(-15, dio.getVersionNumber());
        Assert.assertEquals(768, dio.getRank());
        Assert.assertEquals(8, dio.getFlags());
        Assert.assertEquals((byte) 0xF0, dio.getDtsn());
        Assert.assertEquals(16, dio.getDodagId().length);
        Assert.assertEquals(3, dio.getOptions().size());

        Assert.assertArrayEquals(dioBytes, dio.toByteArray());
    }

    @Test
    public void daoTest() {
        byte[] daoBytes = TestUtils.parseHexBinary("01C0000405060708090A0B0C0D0E0F1011121314");
        RplDao dao = RplDao.decode(ByteBuffer.wrap(daoBytes), false);

        Assert.assertEquals(1, dao.getRplInstance());
        Assert.assertEquals((byte) 0xC0, dao.getFlags());
        Assert.assertEquals(4, dao.getDaoSequence());
        Assert.assertEquals(16, dao.getDodagId().length);
        Assert.assertEquals(0, dao.getOptions().size());

        Assert.assertArrayEquals(daoBytes, dao.toByteArray());

        RplDao dao2 = new RplDao((byte) 0x12, (byte) 0xC0, (byte) 0xF1, new byte[0], new ArrayList<>());
        Assert.assertEquals(0x12, dao2.getRplInstance());
        Assert.assertEquals((byte) 0xC0, dao2.getFlags());
        Assert.assertEquals((byte) 0xF1, dao2.getDaoSequence());
        Assert.assertEquals(0, dao2.getDodagId().length);
        Assert.assertEquals(0, dao2.getOptions().size());
    }

    @Test
    public void daoAckTest() {
        byte[] daoAckBytes = TestUtils.parseHexBinary("0180030405060708090A0B0C0D0E0F1011121314");
        RplDaoAck daoAck = RplDaoAck.decode(ByteBuffer.wrap(daoAckBytes), false);

        Assert.assertEquals(1, daoAck.getRplInstance());
        Assert.assertEquals((byte) 0x80, daoAck.getFlags());
        Assert.assertEquals(3, daoAck.getDaoSequence());
        Assert.assertEquals(4, daoAck.getStatus());
        Assert.assertEquals(16, daoAck.getDodagId().length);
        Assert.assertEquals(0, daoAck.getOptions().size());

        Assert.assertArrayEquals(daoAckBytes, daoAck.toByteArray());
    }

    @Test
    public void ccTest() {
        byte[] ccBytes = TestUtils.parseHexBinary("0000000012345678FF008044441234567812345678123456781234567812345678");
        RplConsistencyCheck cc = RplConsistencyCheck.decode(ByteBuffer.wrap(ccBytes));

        Assert.assertTrue(cc.hasSecurity());
        Assert.assertEquals(RplSecurityMode.GROUP_KEY, cc.getSecurity().getSecurityMode());
        Assert.assertEquals(0, cc.getRplInstance());
        Assert.assertEquals((byte) 0x80, cc.getFlags());
        Assert.assertEquals((short) 0x4444, cc.getCcNonce());
        Assert.assertEquals(16, cc.getDodagId().length);
        Assert.assertEquals(0x12345678, cc.getDestinationCounter());
        Assert.assertEquals(0, cc.getOptions().size());

        Assert.assertArrayEquals(ccBytes, cc.toByteArray());
    }
}
