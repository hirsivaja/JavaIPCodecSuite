package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RoutingExtension(
        IpProtocol nextHeader,
        byte routingType,
        byte segmentsLeft,
        int routingTypeData,
        List<Long> extraOptions) implements ExtensionHeader {

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) extraOptions.size());
        out.put(routingType);
        out.put(segmentsLeft);
        out.putInt(routingTypeData);
        for(long extraOption : extraOptions) {
            out.putLong(extraOption);
        }
    }

    @Override
    public int length() {
        return 8 + (extraOptions.size() * 8);
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        byte extensionLen = in.get();
        byte routingType = in.get();
        byte segmentsLeft = in.get();
        int routingTypeData = in.getInt();
        List<Long> extraOptions = new ArrayList<>();
        for(int i = 0; i < extensionLen; i++) {
            extraOptions.add(in.getLong());
        }
        return new RoutingExtension(nextHeader, routingType, segmentsLeft, routingTypeData, extraOptions);
    }
}
