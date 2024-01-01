package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public class GenericIgmpV0Message implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final int identifier;
    private final Ipv4Address groupAddress;
    private final long accessKey;

    public GenericIgmpV0Message(IgmpType type, byte code, int identifier, Ipv4Address groupAddress, long accessKey) {
        this.type = type;
        this.code = code;
        this.identifier = identifier;
        this.groupAddress = groupAddress;
        this.accessKey = accessKey;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(identifier);
        groupAddress.encode(out);
        out.putLong(accessKey);
    }

    @Override
    public int getLength() {
        return 16;
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        int identifier = in.getInt();
        Ipv4Address groupAddress = Ipv4Address.decode(in);
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

    public Ipv4Address getGroupAddress() {
        return groupAddress;
    }

    public long getAccessKey() {
        return accessKey;
    }
}
