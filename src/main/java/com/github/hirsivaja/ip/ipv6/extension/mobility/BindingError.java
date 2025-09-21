package com.github.hirsivaja.ip.ipv6.extension.mobility;


import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record BindingError(
        byte status,
        Ipv6Address homeAddress,
        List<MobilityOption> options) implements MobilityMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.put(status);
        out.put((byte) 0); // RESERVED
        homeAddress.encode(out);
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 18 + options.stream().mapToInt(MobilityOption::length).sum();
    }

    @Override
    public MobilityMessageType type() {
        return MobilityMessageType.BINDING_ERROR;
    }

    public static BindingError decode(ByteBuffer in) {
        byte status = in.get();
        in.get(); // RESERVED
        Ipv6Address homeAddress = Ipv6Address.decode(in);
        List<MobilityOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            options.add(MobilityOption.decode(in));
        }
        return new BindingError(status, homeAddress, options);
    }
}
