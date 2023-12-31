package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public class GenericIgmpV1Message implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final int groupAddress;

    public GenericIgmpV1Message(IgmpType type, byte code, int groupAddress) {
        this.type = type;
        this.code = code;
        this.groupAddress = groupAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(groupAddress);
    }

    @Override
    public int getLength() {
        return 4;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        int groupAddress = in.getInt();
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

    public int getGroupAddress() {
        return groupAddress;
    }
}
