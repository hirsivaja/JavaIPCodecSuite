package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record DestinationUnreachable(byte code, short nextHopMtu, ByteArray payload) implements Icmpv6Message {

    public DestinationUnreachable(byte code, short nextHopMtu, byte[] payload) {
        this(code, nextHopMtu, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort(nextHopMtu);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + payload.length();
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        in.getShort(); // UNUSED
        short nextHopMtu = in.getShort();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new DestinationUnreachable(code, nextHopMtu, payload);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Type.DESTINATION_UNREACHABLE;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
