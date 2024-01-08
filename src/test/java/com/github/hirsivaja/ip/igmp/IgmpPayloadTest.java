package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import com.github.hirsivaja.ip.ipv4.Ipv4Payload;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class IgmpPayloadTest {

    @Test
    public void membershipReportV0Test() {
        byte[] reqBytes = TestUtils.parseHexBinary("0101048412345678876543211234567890ABCDEF");
        Ipv4Header header = new Ipv4Header((byte) 0, IpHeader.EcnCodePoint.NO_ECN_NO_ECT, (short) 0, (short) 0, null, (short) 0, (byte) 0, IpProtocol.ICMP, null, null, null);

        IgmpPayload payload = (IgmpPayload) IgmpPayload.decode(ByteBuffer.wrap(reqBytes), header);
        GenericIgmpV0Message msg = (GenericIgmpV0Message) payload.getMessage();

        Assert.assertEquals(0x12345678, msg.getIdentifier());
        Assert.assertEquals(0x87654321, msg.getGroupAddress().toInt());
        Assert.assertEquals(0x1234567890ABCDEFL, msg.getAccessKey());
        Assert.assertEquals(20, msg.getLength());

        Assert.assertArrayEquals(Arrays.copyOfRange(reqBytes, 4, reqBytes.length), TestUtils.toBytes(msg));
    }

    @Test
    public void membershipReportV1Test() {
        byte[] reqBytes = TestUtils.parseHexBinary("1200FE04EFFFFFFA");
        Ipv4Header header = new Ipv4Header((byte) 0, IpHeader.EcnCodePoint.NO_ECN_NO_ECT, (short) 0, (short) 0, null, (short) 0, (byte) 0, IpProtocol.ICMP, null, null, null);

        IgmpPayload payload = (IgmpPayload) IgmpPayload.decode(ByteBuffer.wrap(reqBytes), header);
        GenericIgmpV1Message msg = (GenericIgmpV1Message) payload.getMessage();

        Assert.assertEquals(0xEFFFFFFA, msg.getGroupAddress().toInt());
        Assert.assertEquals(8, msg.getLength());

        Assert.assertArrayEquals(Arrays.copyOfRange(reqBytes, 4, reqBytes.length), TestUtils.toBytes(msg));
    }

    @Test
    public void membershipQueryV2Test() {
        byte[] reqBytes = TestUtils.parseHexBinary("45C0001CF8D800000102D54D0A3C00BDE00000011164EE9B00000000");
        IpPayload ipv4Payload = Ipv4Payload.decode(ByteBuffer.wrap(reqBytes));

        Assert.assertTrue(ipv4Payload instanceof Ipv4Payload);
        Assert.assertTrue(((IgmpPayload) ipv4Payload).getMessage() instanceof GenericIgmpV2Message);
        GenericIgmpV2Message query = (GenericIgmpV2Message) ((IgmpPayload) ipv4Payload).getMessage();
        Assert.assertEquals(0x64, query.getMaxRespCode());
        Assert.assertEquals(0, query.getGroupAddress().toInt());

        Assert.assertArrayEquals(reqBytes, TestUtils.toBytes(ipv4Payload));
    }

    @Test
    public void membershipQueryV3Test() {
        byte[] reqBytes = TestUtils.parseHexBinary("450100380000000040024DC600FF2BFFFFFFFFFF11604DC92100BAF1455000060030000000509999999999999999999999013000B51500F7");
        IpPayload ipv4Payload = Ipv4Payload.decode(ByteBuffer.wrap(reqBytes));

        Assert.assertTrue(ipv4Payload instanceof Ipv4Payload);
        Assert.assertTrue(((IgmpPayload) ipv4Payload).getMessage() instanceof MembershipQueryMessage);
        MembershipQueryMessage query = (MembershipQueryMessage) ((IgmpPayload) ipv4Payload).getMessage();
        Assert.assertEquals(0x60, query.getMaxRespCode());
        Assert.assertEquals(0x2100BAF1, query.getGroupAddress().toInt());
        Assert.assertEquals(0x45, query.getFlags());
        Assert.assertEquals(0x50, query.getQqic());
        Assert.assertEquals(6, query.getSourceAddresses().length);

        Assert.assertArrayEquals(reqBytes, TestUtils.toBytes(ipv4Payload));
    }

    @Test
    public void membershipReportV3Test() {
        byte[] reqBytes = TestUtils.parseHexBinary("456200430D0000002E029533E9E9000D0000002E22642AC300000001060F0004F00700CBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCBCB");
        IpPayload ipv4Payload = Ipv4Payload.decode(ByteBuffer.wrap(reqBytes));

        Assert.assertTrue(ipv4Payload instanceof Ipv4Payload);
        Assert.assertTrue(((IgmpPayload) ipv4Payload).getMessage() instanceof MembershipReportV3Message);
        MembershipReportV3Message report = (MembershipReportV3Message) ((IgmpPayload) ipv4Payload).getMessage();
        Assert.assertEquals(1, report.getGroupRecords().length);
        GroupRecord record1 = report.getGroupRecords()[0];
        Assert.assertEquals(6, record1.getRecordType());
        Assert.assertEquals(0xF00700CB, record1.getMulticastAddress().toInt());
        Assert.assertEquals(4, record1.getSourceAddresses().length);
        Assert.assertEquals(15, record1.getAuxData().length);

        Assert.assertArrayEquals(reqBytes, TestUtils.toBytes(ipv4Payload));
    }
}
