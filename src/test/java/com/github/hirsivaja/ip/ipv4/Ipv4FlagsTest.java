package com.github.hirsivaja.ip.ipv4;

import org.junit.Assert;
import org.junit.Test;

public class Ipv4FlagsTest {

    @Test
    public void flagTest() {
        byte allOn = (byte) 0x7;
        Ipv4Flags on = Ipv4Flags.decode(allOn);
        Assert.assertEquals(allOn, on.toByte());
        Assert.assertTrue(on.isMoreFragments());
        Assert.assertTrue(on.isDoNotFragment());
        Assert.assertTrue(on.isReservedFlag());

        byte allOff = (byte) 0x0;
        Ipv4Flags off = Ipv4Flags.decode(allOff);
        Assert.assertEquals(allOff, off.toByte());
        Assert.assertFalse(off.isMoreFragments());
        Assert.assertFalse(off.isDoNotFragment());
        Assert.assertFalse(off.isReservedFlag());
    }
}
