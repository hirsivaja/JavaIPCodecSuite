package com.github.hirsivaja.ip.icmp;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import java.nio.ByteBuffer;

public record Redirect(IcmpCode code, Ipv4Address address, ByteArray payload) implements IcmpMessage {
    public Redirect(IcmpCode code, Ipv4Address address, byte[] payload) {
        this(code, address, new ByteArray(payload));
    }

    @Override
    public void encode(ByteBuffer out) {
        address.encode(out);
        out.put(payload.array());
    }

    @Override
    public int length() {
        return 4 + payload.array().length;
    }

    public static IcmpMessage decode(ByteBuffer in, IcmpCode code) {
        Ipv4Address address = Ipv4Address.decode(in);
        byte[] payload = new byte[in.remaining()];
        in.get(payload);
        return new Redirect(code, address, payload);
    }

    @Override
    public IcmpType type() {
        return IcmpTypes.REDIRECT_MESSAGE;
    }

    public byte[] rawPayload() {
        return payload.array();
    }
}
