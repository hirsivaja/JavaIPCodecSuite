package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public class DestinationUnreachable implements Icmpv6Message {
    private final byte code;
    private final short nextHopMtu;
    private final byte[] payload;

    public DestinationUnreachable(byte code, short nextHopMtu, byte[] payload) {
        this.code = code;
        this.nextHopMtu = nextHopMtu;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        out.putShort(nextHopMtu);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return BASE_LEN + 4 + payload.length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        in.getShort(); // UNUSED
        short nextHopMtu = in.getShort();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new DestinationUnreachable(code, nextHopMtu, payload);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.DESTINATION_UNREACHABLE;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public short getNextHopMtu() {
        return nextHopMtu;
    }

    public byte[] getPayload() {
        return payload;
    }
}
