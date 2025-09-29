package com.github.hirsivaja.ip.icmpv6.rpl;

import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Packet;
import com.github.hirsivaja.ip.ipv6.Ipv6Header;
import com.github.hirsivaja.ip.ipv6.Ipv6Packet;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class RplControlMessageTest {

    @Test
    public void dioTest() {
        byte[] headerBytes = IpUtils.parseHexBinary("6000000000563A40FE80000000000000020A000A000A000AFF02000000000000000000000000001A");
        byte[] msg = IpUtils.parseHexBinary("9B010DD11EF1030008F00000FD000000000000000218001800180018020607000002030002200102011C0000011802100010001000100210001000100010020F000F000F000F040E00080C0A038000800001001E003C");

        Ipv6Header header = Ipv6Header.decode(ByteBuffer.wrap(headerBytes));
        Ipv6Packet dio = Icmpv6Packet.decode(ByteBuffer.wrap(msg), header);

        byte[] outBytes = TestUtils.toBytes(dio);
        Assert.assertArrayEquals(msg, Arrays.copyOfRange(outBytes, 40, outBytes.length));
    }
}
