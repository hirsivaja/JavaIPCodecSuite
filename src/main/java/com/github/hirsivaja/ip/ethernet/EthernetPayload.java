package com.github.hirsivaja.ip.ethernet;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpPacket;

import java.nio.ByteBuffer;
import java.util.Arrays;

public sealed interface EthernetPayload permits ArpPacket, IpPacket, EthernetPayload.GenericEthernetPayload {
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
            return GenericEthernetPayload.decode(in, len);
        }
        return switch (len) {
            case ARP -> ArpPacket.decode(in);
            case IPV4, IPV6 -> IpPacket.decode(in);
            default -> GenericEthernetPayload.decode(in);
        };
    }

    record GenericEthernetPayload(ByteArray payload) implements EthernetPayload {

        public GenericEthernetPayload(byte[] payload) {
            this(new ByteArray(payload));
        }

        @Override
        public void encode(ByteBuffer out) {
            out.put(payload.array());
        }

        @Override
        public int length() {
            return payload.array().length;
        }

        public static GenericEthernetPayload decode(ByteBuffer in) {
            return decode(in, in.remaining());
        }

        public static GenericEthernetPayload decode(ByteBuffer in, int len) {
            byte[] payload = new byte[len];
            in.get(payload);
            return new GenericEthernetPayload(payload);
        }
    }
}
