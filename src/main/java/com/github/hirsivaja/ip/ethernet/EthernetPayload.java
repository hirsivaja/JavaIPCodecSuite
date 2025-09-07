package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpPayload;

import java.nio.ByteBuffer;
import java.util.Arrays;

public sealed interface EthernetPayload permits ArpPacket, EthernetBytePayload, IpPayload {
    int MAX_PAYLOAD_SIZE = 1500;
    int ARP = 0x0806;
    int IPV4 = 0x0800;
    int IPV6 = 0x86DD;
    void encode(ByteBuffer out);
    int length();

    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(length());
        encode(out);
        return Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
    }

    static EthernetPayload decode(ByteBuffer in, int len) {
        if(len <= MAX_PAYLOAD_SIZE) {
            return EthernetBytePayload.decode(in, len);
        }
        return switch (len) {
            case ARP -> ArpPacket.decode(in);
            case IPV4, IPV6 -> IpPayload.decode(in);
            default -> throw new IllegalArgumentException("Ethernet payload type " + len + " is not supported.");
        };
    }
}
