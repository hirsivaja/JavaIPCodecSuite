package com.github.hirsivaja.ip.icmpv6;

import java.nio.ByteBuffer;

public class PacketTooBig implements Icmpv6Message {
    private final byte code;
    private final int mtu;
    private final byte[] payload;

    public PacketTooBig(byte code, int mtu, byte[] payload) {
        this.code = code;
        this.mtu = mtu;
        this.payload = payload;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(mtu);
        out.put(payload);
    }

    @Override
    public int getLength() {
        return 4 + payload.length;
    }

    public static Icmpv6Message decode(ByteBuffer in, byte code) {
        int mtu = in.getInt();
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new PacketTooBig(code, mtu, payload);
    }

    @Override
    public Icmpv6Type getType() {
        return Icmpv6Type.PACKET_TOO_BIG;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public int getMtu() {
        return mtu;
    }

    public byte[] getPayload() {
        return payload;
    }
}
