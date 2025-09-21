package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record BindingRefreshRequest(List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort((short) 0);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 2 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.BINDING_REFRESH_REQUEST;
    }

    public static BindingRefreshRequest decode(ByteBuffer in) {
        in.getShort(); // RESERVED
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new BindingRefreshRequest(options);
    }
}
