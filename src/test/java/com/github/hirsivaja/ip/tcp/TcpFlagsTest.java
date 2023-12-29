package com.github.hirsivaja.ip.tcp;

import org.junit.Assert;
import org.junit.Test;

public class TcpFlagsTest {

    @Test
    public void flagTest() {
        byte allOn = (byte) 0xFF;
        TcpFlags on = TcpFlags.decode(allOn);
        Assert.assertEquals(allOn, on.toByte());

        byte allOff = (byte) 0x00;
        TcpFlags off = TcpFlags.decode(allOff);
        Assert.assertEquals(allOff, off.toByte());

        byte halfOff = (byte) 0xAA;
        TcpFlags offHalf = TcpFlags.decode(halfOff);
        Assert.assertEquals(halfOff, offHalf.toByte());
        Assert.assertTrue(offHalf.isCongestionWindowReduced());
        Assert.assertFalse(offHalf.isEceFlag());
        Assert.assertTrue(offHalf.isUrgentPointerSignificant());
        Assert.assertFalse(offHalf.isAcknowledgementSignificant());
        Assert.assertTrue(offHalf.isPushFunction());
        Assert.assertFalse(offHalf.isReset());
        Assert.assertTrue(offHalf.isSynchronizeSequenceNumbers());
        Assert.assertFalse(offHalf.isLastPacket());
        Assert.assertFalse(offHalf.isExplicitCongestionNotificationCapable());

        byte halfOn = (byte) 0x55;
        TcpFlags onHalf = TcpFlags.decode(halfOn);
        Assert.assertEquals(halfOn, onHalf.toByte());
        Assert.assertFalse(onHalf.isCongestionWindowReduced());
        Assert.assertTrue(onHalf.isEceFlag());
        Assert.assertFalse(onHalf.isUrgentPointerSignificant());
        Assert.assertTrue(onHalf.isAcknowledgementSignificant());
        Assert.assertFalse(onHalf.isPushFunction());
        Assert.assertTrue(onHalf.isReset());
        Assert.assertFalse(onHalf.isSynchronizeSequenceNumbers());
        Assert.assertTrue(onHalf.isLastPacket());
        Assert.assertFalse(offHalf.isExplicitCongestionNotificationCapable());
    }
}
