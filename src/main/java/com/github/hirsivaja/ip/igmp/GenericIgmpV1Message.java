package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public record GenericIgmpV1Message(IgmpType type, byte code, Ipv4Address groupAddress) implements IgmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        groupAddress.encode(out);
    }

    @Override
    public int length() {
        return BASE_LEN + 4;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        return new GenericIgmpV1Message(type, code, groupAddress);
    }
}
