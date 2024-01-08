package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public class GenericIgmpV1Message implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final Ipv4Address groupAddress;

    public GenericIgmpV1Message(IgmpType type, byte code, Ipv4Address groupAddress) {
        this.type = type;
        this.code = code;
        this.groupAddress = groupAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        groupAddress.encode(out);
    }

    @Override
    public int getLength() {
        return BASE_LEN + 4;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        return new GenericIgmpV1Message(type, code, groupAddress);
    }

    @Override
    public IgmpType getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public Ipv4Address getGroupAddress() {
        return groupAddress;
    }
}
