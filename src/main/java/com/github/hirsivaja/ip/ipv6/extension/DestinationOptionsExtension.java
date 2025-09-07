package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public record DestinationOptionsExtension(
        IpProtocol nextHeader,
        short options,
        int padding,
        ByteArray extraOptions) implements ExtensionHeader {

    public DestinationOptionsExtension(IpProtocol nextHeader, short options, int padding, byte[] extraOptions) {
        this(nextHeader, options, padding, new ByteArray(extraOptions));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) extraOptions.length());
        out.putShort(options);
        out.putInt(padding);
        out.put(extraOptions.array());
    }

    @Override
    public int length() {
        return 8 + extraOptions.length();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        byte extensionLen = in.get();
        short options = in.getShort();
        int padding = in.getInt();
        byte[] extraOptions = new byte[extensionLen];
        in.get(extraOptions);
        return new DestinationOptionsExtension(nextHeader, options, padding, extraOptions);
    }
}
