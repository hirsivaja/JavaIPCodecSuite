package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public record GenericIgmpV2Message(IgmpType type, byte code, Ipv4Address groupAddress) implements IgmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        groupAddress.encode(out);
    }

    @Override
    public int length() {
        return 4;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        return new GenericIgmpV2Message(type, code, groupAddress);
    }

    public byte maxRespCode() {
        return code();
    }
}
