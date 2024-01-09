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
}
