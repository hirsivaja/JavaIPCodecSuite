package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public class DestinationOptionsExtension implements ExtensionHeader {
    private final IpProtocol nextHeader;
    private final short options;
    private final int padding;
    private final byte[] extraOptions;

    public DestinationOptionsExtension(IpProtocol nextHeader, short options, int padding, byte[] extraOptions) {
        this.nextHeader = nextHeader;
        this.options = options;
        this.padding = padding;
        this.extraOptions = extraOptions;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.getType());
        out.put((byte) extraOptions.length);
        out.putShort(options);
        out.putInt(padding);
        out.put(extraOptions);
    }

    @Override
    public int getLength() {
        return 8 + extraOptions.length;
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.getType(in.get());
        byte extensionLen = in.get();
        short options = in.getShort();
        int padding = in.getInt();
        byte[] extraOptions = new byte[extensionLen];
        in.get(extraOptions);
        return new DestinationOptionsExtension(nextHeader, options, padding, extraOptions);
    }

    @Override
    public IpProtocol getNextHeader() {
        return nextHeader;
    }
}
