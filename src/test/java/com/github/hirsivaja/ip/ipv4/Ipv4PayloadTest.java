package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.IpProtocols;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class Ipv4PayloadTest {
    @Test
    public void codecTest() {
        byte[] ipv4Bytes = IpUtils.parseHexBinary("45000050935A0000802967C64637D5D3C0586301600000000014068020024637D5D30000000000004637D5D3200148600000200100000000000000680507005022EC582E3AC018C550104248B8B30000");
        Assert.assertTrue(Ipv4Payload.isIpv4Payload(ByteBuffer.wrap(ipv4Bytes)));

        IpPayload payload = Ipv4Payload.decode(ByteBuffer.wrap(ipv4Bytes));
        Ipv4Header header = (Ipv4Header) payload.header();

        Assert.assertTrue(payload instanceof EncapsulationPayload);
        Assert.assertEquals(60, ((EncapsulationPayload) payload).encapsulatedPayload().length());
        Assert.assertEquals(0, header.dscp());
        Assert.assertEquals(0, header.ecn().type());
        Assert.assertEquals((short) 0x0050, header.totalLength());
        Assert.assertEquals((short) 0x003C, header.dataLength());
        Assert.assertEquals((short) 0x003C, header.payloadLength());
        Assert.assertEquals((short) 0x0014, header.length());
        Assert.assertEquals((short) 0x935A, header.identification());
        Assert.assertEquals(0, header.flags().toByte());
        Assert.assertEquals(0, header.fragmentOffset());
        Assert.assertEquals((byte) 0x80, header.ttl());
        Assert.assertEquals(IpProtocols.IPV6_ENCAPSULATION, header.protocol());
        Assert.assertEquals(0x4637D5D3, header.srcIp().toInt());
        Assert.assertEquals(0xC0586301, header.dstIp().toInt());
        Assert.assertEquals(0, header.options().length());
        Assert.assertEquals(0x50, payload.length());

        Assert.assertArrayEquals(ipv4Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void optionsTest() {
        byte[] ipv4Bytes = IpUtils.parseHexBinary("46000028000040000102D0FBC0A8071AE0000016940400002200F9020000000104000000E00000FB");
        Assert.assertTrue(Ipv4Payload.isIpv4Payload(ByteBuffer.wrap(ipv4Bytes)));

        IpPayload payload = Ipv4Payload.decode(ByteBuffer.wrap(ipv4Bytes));
        Ipv4Header header = (Ipv4Header) payload.header();

        Assert.assertEquals(4, header.options().length());
        Assert.assertEquals(0x28, payload.length());

        Assert.assertArrayEquals(ipv4Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void tcpPayloadTest() {
        byte[] ipv4Bytes = IpUtils.parseHexBinary("4500031F1D2540008006C8C5C0A8C887C0A8C8151EC407D06AF09F2E6F9B26E0501804027C66000020496E7465726E6574205374616E64617264732070726F63657373206D7573742062650A202020666F6C6C6F7765642C206F7220617320726571756972656420746F207472616E736C61746520697420696E746F206C616E677561676573206F74686572207468616E0A202020456E676C6973682E0A0A202020546865206C696D69746564207065726D697373696F6E73206772616E7465642061626F7665206172652070657270657475616C20616E642077696C6C206E6F742062650A2020207265766F6B65642062792074686520496E7465726E657420536F6369657479206F722069747320737563636573736F7273206F722061737369676E732E0A0A2020205468697320646F63756D656E7420616E642074686520696E666F726D6174696F6E20636F6E7461696E65642068657265696E2069732070726F7669646564206F6E20616E0A2020202241532049532220626173697320616E642054484520494E5445524E455420534F434945545920414E442054484520494E5445524E455420454E47494E454552494E470A2020205441534B20464F52434520444953434C41494D5320414C4C2057415252414E544945532C2045585052455353204F5220494D504C4945442C20494E434C5544494E470A202020425554204E4F54204C494D4954454420544F20414E592057415252414E545920544841542054484520555345204F462054484520494E464F524D4154494F4E0A20202048455245494E2057494C4C204E4F5420494E4652494E474520414E5920524947485453204F5220414E5920494D504C4945442057415252414E54494553204F460A2020204D45524348414E544142494C495459204F52204649544E45535320464F52204120504152544943554C415220505552504F53452E0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A576169747A6D616E202020202020202020202020202020202020202020204578706572696D656E74616C202020202020202020202020202020202020202020205B5061676520365D0A0C0A");
        IpPayload payload = Ipv4Payload.decode(ByteBuffer.wrap(ipv4Bytes));

        Assert.assertArrayEquals(ipv4Bytes, TestUtils.toBytes(payload));
    }

    @Test
    public void authenticationTest() {
        byte[] ipv4Bytes = IpUtils.parseHexBinary("45000074000040000133D17EC0A8071AE00000162902000012345678123456781234567845000050935A0000802967C64637D5D3C0586301600000000014068020024637D5D30000000000004637D5D3200148600000200100000000000000680507005022EC582E3AC018C550104248B8B30000");
        Assert.assertTrue(Ipv4Payload.isIpv4Payload(ByteBuffer.wrap(ipv4Bytes)));

        IpPayload payload = Ipv4Payload.decode(ByteBuffer.wrap(ipv4Bytes));
        Ipv4Header header = (Ipv4Header) payload.header();

        Assert.assertEquals(0, header.options().length());
        Assert.assertTrue(payload instanceof AuthenticationPayload);
        AuthenticationPayload authenticationPayload = (AuthenticationPayload) payload;
        Assert.assertTrue(authenticationPayload.authenticatedPayload() instanceof EncapsulationPayload);
        Assert.assertEquals(16, authenticationPayload.authenticationHeader().length());

        Assert.assertArrayEquals(ipv4Bytes, TestUtils.toBytes(payload));
    }
}
