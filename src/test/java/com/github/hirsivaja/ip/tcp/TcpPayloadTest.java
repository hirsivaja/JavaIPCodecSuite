package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.TestUtils;
import com.github.hirsivaja.ip.ipv4.Ipv4Header;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class TcpPayloadTest {

    @Test
    public void tcpTest() {
        byte[] ipv4HeaderBytes = TestUtils.parseHexBinary("4500031F1D2540008006C8C5C0A8C887C0A8C815");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] tcpBytes = TestUtils.parseHexBinary("1EC407D06AF09F2E6F9B26E0501804027C66000020496E7465726E6574205374616E64617264732070726F63657373206D7573742062650A202020666F6C6C6F7765642C206F7220617320726571756972656420746F207472616E736C61746520697420696E746F206C616E677561676573206F74686572207468616E0A202020456E676C6973682E0A0A202020546865206C696D69746564207065726D697373696F6E73206772616E7465642061626F7665206172652070657270657475616C20616E642077696C6C206E6F742062650A2020207265766F6B65642062792074686520496E7465726E657420536F6369657479206F722069747320737563636573736F7273206F722061737369676E732E0A0A2020205468697320646F63756D656E7420616E642074686520696E666F726D6174696F6E20636F6E7461696E65642068657265696E2069732070726F7669646564206F6E20616E0A2020202241532049532220626173697320616E642054484520494E5445524E455420534F434945545920414E442054484520494E5445524E455420454E47494E454552494E470A2020205441534B20464F52434520444953434C41494D5320414C4C2057415252414E544945532C2045585052455353204F5220494D504C4945442C20494E434C5544494E470A202020425554204E4F54204C494D4954454420544F20414E592057415252414E545920544841542054484520555345204F462054484520494E464F524D4154494F4E0A20202048455245494E2057494C4C204E4F5420494E4652494E474520414E5920524947485453204F5220414E5920494D504C4945442057415252414E54494553204F460A2020204D45524348414E544142494C495459204F52204649544E45535320464F52204120504152544943554C415220505552504F53452E0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A576169747A6D616E202020202020202020202020202020202020202020204578706572696D656E74616C202020202020202020202020202020202020202020205B5061676520365D0A0C0A");
        TcpMessagePayload payload = (TcpMessagePayload) TcpMessagePayload.decode(ByteBuffer.wrap(tcpBytes), ipv4Header);

        TcpHeader tcpHeader = payload.getTcpHeader();
        Assert.assertEquals(7876, tcpHeader.getSrcPort());
        Assert.assertEquals(2000, tcpHeader.getDstPort());
        Assert.assertEquals(0x6AF09F2E, tcpHeader.getSequenceNumber());
        Assert.assertEquals(0x6F9B26E0, tcpHeader.getAckNumber());
        Assert.assertEquals(0x18, tcpHeader.getFlags());
        Assert.assertEquals(0x0402, tcpHeader.getWindowSize());
        Assert.assertEquals((short) 0x7C66, tcpHeader.getChecksum());
        Assert.assertEquals(0x0000, tcpHeader.getUrgentPointer());
        Assert.assertEquals(759, payload.getPayload().length);

        byte[] outBytes = TestUtils.toBytes(payload);
        Assert.assertArrayEquals(tcpBytes, Arrays.copyOfRange(outBytes, 20, outBytes.length));
    }

    @Test
    public void instantiationTest() {
        byte[] ipv4HeaderBytes = TestUtils.parseHexBinary("4500031F1D2540008006C8C5C0A8C887C0A8C815");
        Ipv4Header ipv4Header = Ipv4Header.decode(ByteBuffer.wrap(ipv4HeaderBytes));
        byte[] tcpData = TestUtils.parseHexBinary("20496E7465726E6574205374616E64617264732070726F63657373206D7573742062650A202020666F6C6C6F7765642C206F7220617320726571756972656420746F207472616E736C61746520697420696E746F206C616E677561676573206F74686572207468616E0A202020456E676C6973682E0A0A202020546865206C696D69746564207065726D697373696F6E73206772616E7465642061626F7665206172652070657270657475616C20616E642077696C6C206E6F742062650A2020207265766F6B65642062792074686520496E7465726E657420536F6369657479206F722069747320737563636573736F7273206F722061737369676E732E0A0A2020205468697320646F63756D656E7420616E642074686520696E666F726D6174696F6E20636F6E7461696E65642068657265696E2069732070726F7669646564206F6E20616E0A2020202241532049532220626173697320616E642054484520494E5445524E455420534F434945545920414E442054484520494E5445524E455420454E47494E454552494E470A2020205441534B20464F52434520444953434C41494D5320414C4C2057415252414E544945532C2045585052455353204F5220494D504C4945442C20494E434C5544494E470A202020425554204E4F54204C494D4954454420544F20414E592057415252414E545920544841542054484520555345204F462054484520494E464F524D4154494F4E0A20202048455245494E2057494C4C204E4F5420494E4652494E474520414E5920524947485453204F5220414E5920494D504C4945442057415252414E54494553204F460A2020204D45524348414E544142494C495459204F52204649544E45535320464F52204120504152544943554C415220505552504F53452E0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A576169747A6D616E202020202020202020202020202020202020202020204578706572696D656E74616C202020202020202020202020202020202020202020205B5061676520365D0A0C0A");
        TcpHeader tcpHeaderIn = new TcpHeader((short) 7876, (short) 2000, 0x6AF09F2E, 0x6F9B26E0, (byte) 0x18, (short) 0x0402, (short) 0x0000, new byte[0]);
        TcpMessagePayload payload = new TcpMessagePayload(ipv4Header, tcpHeaderIn, tcpData);
        TcpHeader tcpHeader = payload.getTcpHeader();

        Assert.assertEquals(7876, tcpHeader.getSrcPort());
        Assert.assertEquals(2000, tcpHeader.getDstPort());
        Assert.assertEquals(0x6AF09F2E, tcpHeader.getSequenceNumber());
        Assert.assertEquals(0x6F9B26E0, tcpHeader.getAckNumber());
        Assert.assertEquals(0x18, tcpHeader.getFlags());
        Assert.assertEquals(0x0402, tcpHeader.getWindowSize());
        Assert.assertEquals((short) 0x7C66, tcpHeader.getChecksum());
        Assert.assertEquals(0x0000, tcpHeader.getUrgentPointer());
        Assert.assertEquals(759, payload.getPayload().length);
    }
}