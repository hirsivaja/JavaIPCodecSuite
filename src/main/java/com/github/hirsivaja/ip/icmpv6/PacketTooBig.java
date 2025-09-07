package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record PacketTooBig(byte code, int mtu, ByteArray payload) implements Icmpv6Message {

    public PacketTooBig(byte code, int mtu, byte[] payload) {
        this(code, mtu, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(mtu);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + payload.array().length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        int mtu = in.getInt();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new PacketTooBig(code, mtu, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.PACKET_TOO_BIG;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
