package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public class RoutingExtension implements ExtensionHeader {
    private final IpProtocol nextHeader;
    private final byte routingType;
    private final byte segmentsLeft;
    private final int routingTypeData;
    private final long[] extraOptions;

    public RoutingExtension(IpProtocol nextHeader, byte routingType, byte segmentsLeft, int routingTypeData, long[] extraOptions) {
        this.nextHeader = nextHeader;
        this.routingType = routingType;
        this.segmentsLeft = segmentsLeft;
        this.routingTypeData = routingTypeData;
        this.extraOptions = extraOptions;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.getType());
        out.put((byte) extraOptions.length);
        out.put(routingType);
        out.put(segmentsLeft);
        out.putInt(routingTypeData);
        for(long extraOption : extraOptions) {
            out.putLong(extraOption);
        }
    }

    @Override
    public int getLength() {
        return 8 + (extraOptions.length * 8);
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.getType(in.get());
        byte extensionLen = in.get();
        byte routingType = in.get();
        byte segmentsLeft = in.get();
        int routingTypeData = in.getInt();
        long[] extraOptions = new long[extensionLen];
        for(int i = 0; i < extensionLen; i++) {
            extraOptions[i] = in.getLong();
        }
        return new RoutingExtension(nextHeader, routingType, segmentsLeft, routingTypeData, extraOptions);
    }

    @Override
    public IpProtocol getNextHeader() {
        return nextHeader;
    }
}
