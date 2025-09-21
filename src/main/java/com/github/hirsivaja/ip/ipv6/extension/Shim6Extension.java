package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public record Shim6Extension(
        IpProtocol nextHeader,
        ByteArray data) implements ExtensionHeader {

    public Shim6Extension(IpProtocol nextHeader, byte[] data) {
        this(nextHeader, new ByteArray(data));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) ((2 + data.length()) / 8));
        out.put(data.array());
    }

    @Override
    public int length() {
        return 2 + data.length();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        int headerLen = Byte.toUnsignedInt(in.get()) * 8;
        byte[] data = new byte[headerLen + 6];
        in.get(data);
        return new Shim6Extension(nextHeader, data);
    }
}
