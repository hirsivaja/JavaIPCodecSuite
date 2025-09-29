package com.github.hirsivaja.ip.icmpv6.rr;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Packet;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class RouterRenumerationMessageTest {

    @Test
    public void sequenceNumberResetTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000103A40FE80000000000000020A000A000A000AFF02000000000000000000000000001A");
        byte[] msg = IpUtils.parseHexBinary("8AFFE7171234567812F8123400000000");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Packet dio = Icmpv6Packet.decode(ByteBuffer.wrap(msg), header);

        byte[] outBytes = TestUtils.toBytes(dio);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }
}
