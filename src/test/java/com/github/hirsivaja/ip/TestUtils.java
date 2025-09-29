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
        switch (object) {
            case IpPacket ipPacket -> {
                out = ByteBuffer.allocate(ipPacket.length());
                ipPacket.encode(out);
            }
            case IpHeader ipHeader -> {
                out = ByteBuffer.allocate(ipHeader.length());
                ipHeader.encode(out);
            }
            case ExtensionHeader extHeader -> {
                out = ByteBuffer.allocate(extHeader.length());
                extHeader.encode(out);
            }
            case UdpHeader udpHeader -> {
                out = ByteBuffer.allocate(udpHeader.length());
                udpHeader.encode(out);
            }
            case TcpHeader tcpHeader -> {
                out = ByteBuffer.allocate(tcpHeader.length());
                tcpHeader.encode(out);
            }
            case RplOption option -> {
                out = ByteBuffer.allocate(option.length());
                option.encode(out);
            }
            case RplSecurity security -> {
                out = ByteBuffer.allocate(security.length());
                security.encode(out);
            }
            case NdpOption option -> {
                out = ByteBuffer.allocate(option.length());
                option.encode(out);
            }
            case IgmpMessage message -> {
                out = ByteBuffer.allocate(message.length() - 4);
                message.encode(out);
            }
            case ArpPacket packet -> {
                out = ByteBuffer.allocate(packet.length());
                packet.encode(out);
            }
            case EthernetFrame frame -> {
                out = ByteBuffer.allocate(frame.length());
                frame.encode(out);
            }
            default -> throw new IllegalArgumentException("Unknown object " + object.getClass().getSimpleName());
        }
        byte[] outBytes = new byte[out.rewind().remaining()];
        out.get(outBytes);
        return outBytes;
    }
}
