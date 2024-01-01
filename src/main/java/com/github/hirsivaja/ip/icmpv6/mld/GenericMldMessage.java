package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;

import java.nio.ByteBuffer;

public class GenericMldMessage implements Icmpv6Message {
    private final Icmpv6Type type;
    private final byte code;
    private final short maximumResponseDelay;
    private final byte[] multicastAddress;

    public GenericMldMessage(Icmpv6Type type, byte code, short maximumResponseDelay, byte[] multicastAddress) {
        this.type = type;
        this.code = code;
        this.maximumResponseDelay = maximumResponseDelay;
        this.multicastAddress = multicastAddress;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(maximumResponseDelay);
        out.putShort((short) 0);
        out.put(multicastAddress);
    }

    @Override
    public int getLength() {
        return 20;
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        short maximumResponseDelay = in.getShort();
        in.getShort(); // RESERVED
        byte[] multicastAddress = new byte[16];
        in.get(multicastAddress);
        return new GenericMldMessage(type, code, maximumResponseDelay, multicastAddress);
    }

    @Override
    public Icmpv6Type getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public short getMaximumResponseDelay() {
        return maximumResponseDelay;
    }

    public byte[] getMulticastAddress() {
        return multicastAddress;
    }
}
