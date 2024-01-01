package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.IpPayload;

import java.nio.ByteBuffer;
import java.util.Arrays;

public interface EthernetPayload {
    int MAX_PAYLOAD_SIZE = 1500;
    int ARP = 0x0806;
    int IPV4 = 0x0800;
    int IPV6 = 0x86DD;
    void encode(ByteBuffer out);
    int getLength();

    default byte[] toBytes() {
        ByteBuffer out = ByteBuffer.allocate(getLength());
        encode(out);
        return Arrays.copyOfRange(out.array(), 0, out.rewind().remaining());
    }

    static EthernetPayload decode(ByteBuffer in, int len) {
        if(len <= MAX_PAYLOAD_SIZE) {
            return EthernetBytePayload.decode(in, len);
        }
        switch (len) {
            case ARP:
                return ArpPacket.decode(in);
            case IPV4:
            case IPV6:
                return IpPayload.decode(in);
            default: throw new IllegalArgumentException("Ethernet payload type " + len + " is not supported.");
        }
    }
}
