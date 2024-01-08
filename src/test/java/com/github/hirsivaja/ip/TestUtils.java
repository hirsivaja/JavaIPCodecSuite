package com.github.hirsivaja.ip;

import com.github.hirsivaja.ip.ethernet.ArpPacket;
import com.github.hirsivaja.ip.ethernet.EthernetFrame;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import com.github.hirsivaja.ip.icmpv6.rpl.option.RplOption;
import com.github.hirsivaja.ip.icmpv6.rpl.security.RplSecurity;
import com.github.hirsivaja.ip.igmp.IgmpMessage;
import com.github.hirsivaja.ip.ipv6.extension.ExtensionHeader;
import com.github.hirsivaja.ip.tcp.TcpHeader;
import com.github.hirsivaja.ip.udp.UdpHeader;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class TestUtils {
    public static byte[] toBytes(Object object) {
        ByteBuffer out;
        if(object instanceof IpPayload) {
            IpPayload ipPayload = (IpPayload) object;
            out = ByteBuffer.allocate(ipPayload.getLength());
            ipPayload.encode(out);
        } else if(object instanceof IpHeader) {
            IpHeader ipHeader = (IpHeader) object;
            out = ByteBuffer.allocate(ipHeader.getLength());
            ipHeader.encode(out);
        } else if(object instanceof ExtensionHeader) {
            ExtensionHeader extHeader = (ExtensionHeader) object;
            out = ByteBuffer.allocate(extHeader.getLength());
            extHeader.encode(out);
        } else if(object instanceof UdpHeader) {
            UdpHeader udpHeader = (UdpHeader) object;
            out = ByteBuffer.allocate(udpHeader.getLength());
            udpHeader.encode(out);
        } else if(object instanceof TcpHeader) {
            TcpHeader tcpHeader = (TcpHeader) object;
            out = ByteBuffer.allocate(tcpHeader.getLength());
            tcpHeader.encode(out);
        } else if(object instanceof RplOption) {
            RplOption option = (RplOption) object;
            out = ByteBuffer.allocate(option.getLength());
            option.encode(out);
        } else if(object instanceof RplSecurity) {
            RplSecurity security = (RplSecurity) object;
            out = ByteBuffer.allocate(security.getLength());
            security.encode(out);
        } else if(object instanceof NdpOption) {
            NdpOption option = (NdpOption) object;
            out = ByteBuffer.allocate(option.getLength());
            option.encode(out);
        } else if(object instanceof IgmpMessage) {
            IgmpMessage message = (IgmpMessage) object;
            out = ByteBuffer.allocate(message.getLength() - 4);
            message.encode(out);
        } else if(object instanceof ArpPacket) {
            ArpPacket packet = (ArpPacket) object;
            out = ByteBuffer.allocate(packet.getLength());
            packet.encode(out);
        } else if(object instanceof EthernetFrame) {
            EthernetFrame frame = (EthernetFrame) object;
            out = ByteBuffer.allocate(frame.getLength());
            frame.encode(out);
        } else {
            throw new IllegalArgumentException("Unknown object " + object.getClass().getSimpleName());
        }
        byte[] outBytes = new byte[out.rewind().remaining()];
        out.get(outBytes);
        return outBytes;
    }

    public static byte[] parseHexBinary(String hexString) {
        if(hexString.length() % 2 == 1) {
            hexString = "0" + hexString;
        }
        char[] chars = hexString.toCharArray();
        byte[] bytes = new byte[chars.length / 2];
        for(int i = 0, j = 0; i < chars.length; i += 2, j++) {
            int a = Character.digit(chars[i], 16) << 4;
            int b = Character.digit(chars[i + 1], 16);
            bytes[j] = (byte) (a | b);
        }
        return bytes;
    }

    public static String printHexBinary(byte[] hexBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte hexByte : hexBytes) {
            sb.append(String.format("%02x", hexByte));
        }
        return sb.toString().toUpperCase();
    }

    @Test
    public void parseHexBinaryTest() {
        String testString = "00010203040506078090A0B0C0D0E0F0";
        byte[] testBytes = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                (byte) 0x80, (byte) 0x90, (byte) 0xA0, (byte) 0xB0, (byte) 0xC0, (byte) 0xD0, (byte) 0xE0, (byte) 0xF0};
        Assert.assertArrayEquals(testBytes, TestUtils.parseHexBinary(testString));
    }

    @Test
    public void printHexBinaryTest() {
        String testString = "001020304050607008090A0B0C0D0E0F";
        byte[] testBytes = new byte[]{ 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        Assert.assertEquals(testString, TestUtils.printHexBinary(testBytes));
    }
}
