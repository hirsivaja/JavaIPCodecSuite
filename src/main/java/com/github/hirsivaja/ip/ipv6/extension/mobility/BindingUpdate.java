package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record BindingUpdate(
        short sequenceNumber,
        short flags,
        short lifetime,
        List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(sequenceNumber);
        out.putShort(flags);
        out.putShort(lifetime);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 6 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.BINDING_UPDATE;
    }

    public static BindingUpdate decode(ByteBuffer in) {
        short sequenceNumber = in.getShort();
        short flags = in.getShort();
        short lifetime = in.getShort();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new BindingUpdate(sequenceNumber, flags, lifetime, options);
    }
}
