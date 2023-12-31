package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public class GenericIgmpV0Message implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final int identifier;
    private final int groupAddress;
    private final long accessKey;

    public GenericIgmpV0Message(IgmpType type, byte code, int identifier, int groupAddress, long accessKey) {
        this.type = type;
        this.code = code;
        this.identifier = identifier;
        this.groupAddress = groupAddress;
        this.accessKey = accessKey;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(identifier);
        out.putInt(groupAddress);
        out.putLong(accessKey);
    }

    @Override
    public int getLength() {
        return 16;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        int identifier = in.getInt();
        int groupAddress = in.getInt();
        long accessKey = in.getLong();
        return new GenericIgmpV0Message(type, code, identifier, groupAddress, accessKey);
    }

    @Override
    public IgmpType getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getGroupAddress() {
        return groupAddress;
    }

    public long getAccessKey() {
        return accessKey;
    }
}
