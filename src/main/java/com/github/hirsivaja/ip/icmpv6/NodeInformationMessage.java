package com.github.hirsivaja.ip.icmpv6;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record NodeInformationMessage(
        Icmpv6Code code,
        short qType,
        short flags,
        long nonce,
        ByteArray data) implements Icmpv6Message {

    public NodeInformationMessage(Icmpv6Code code, short qType, short flags, long nonce, byte[] data) {
        this(code, qType, flags, nonce, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(qType);
        out.putShort(flags);
        out.putLong(nonce);
        out.put(data.array());
    }

    @Override
    public int length() {
        return 12 + data.length();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        short qType = in.getShort();
        short flags = in.getShort();
        long nonce = in.getLong();
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new NodeInformationMessage(code, qType, flags, nonce, data);
    }

    @Override
    public Icmpv6Type type() {
        return code.type();
    }

    public byte[] rawData() {
        return data.array();
    }
}
