package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class EthernetFrameTest {

    @Test
    public void arpPacketTest() {
        byte[] ethernetBytes = TestUtils.parseHexBinary("FFFFFFFFFFFFC80E147E339F08060001080006040001C80E147E339FC0A80701000000000000C0A8074E0000000000000000000000000000000000002EBA6C95");
        EthernetFrame ethernetFrame = EthernetFrame.decode(ByteBuffer.wrap(ethernetBytes));

        Assert.assertEquals(6, ethernetFrame.getDestination().getLength());
        Assert.assertEquals(6, ethernetFrame.getSource().getBytes().length);
        Assert.assertFalse(ethernetFrame.hasDot1qTag());
        Assert.assertEquals(0, ethernetFrame.getDot1qTag());
        Assert.assertEquals(28, ethernetFrame.getPayload().getLength());
        Assert.assertEquals(0x2EBA6C95, ethernetFrame.getCrc());

        Assert.assertArrayEquals(ethernetBytes, TestUtils.toBytes(ethernetFrame));
    }
}
