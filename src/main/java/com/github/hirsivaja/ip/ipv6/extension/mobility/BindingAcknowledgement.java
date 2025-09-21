package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record BindingAcknowledgement(
        byte status,
        byte flags,
        short sequenceNumber,
        short lifetime,
        List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.put(status);
        out.put(flags);
        out.putShort(sequenceNumber);
        out.putShort(lifetime);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 6 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.BINDING_ACKNOWLEDGEMENT;
    }

    public static BindingAcknowledgement decode(ByteBuffer in) {
        byte status = in.get();
        byte flags = in.get();
        short sequenceNumber = in.getShort();
        short lifetime = in.getShort();
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new BindingAcknowledgement(status, flags, sequenceNumber, lifetime, options);
    }
}
