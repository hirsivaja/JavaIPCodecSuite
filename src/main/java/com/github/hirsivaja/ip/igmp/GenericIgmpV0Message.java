package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public record GenericIgmpV0Message(
        IgmpType type,
        byte code,
        int identifier,
        Ipv4Address groupAddress,
        long accessKey) implements IgmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(identifier);
        groupAddress.encode(out);
        out.putLong(accessKey);
    }

    @Override
    public int length() {
        return 16;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        int identifier = in.getInt();
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        long accessKey = in.getLong();
        return new GenericIgmpV0Message(type, code, identifier, groupAddress, accessKey);
    }
}
