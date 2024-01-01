package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;

import java.nio.ByteBuffer;

public class MulticastListenerQueryMessage implements Icmpv6Message {
    private final Icmpv6Type type;
    private final byte code;
    private final short maximumResponseCode;
    private final byte[] multicastAddress;
    private final byte flags;
    private final byte qqic;
    private final byte[][] sourceAddresses;

    public MulticastListenerQueryMessage(Icmpv6Type type, byte code, short maximumResponseCode, byte[] multicastAddress,
                                         byte flags, byte qqic, byte[][] sourceAddresses) {
        this.type = type;
        this.code = code;
        this.maximumResponseCode = maximumResponseCode;
        this.multicastAddress = multicastAddress;
        this.flags = flags;
        this.qqic = qqic;
        this.sourceAddresses = sourceAddresses;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(maximumResponseCode);
        out.putShort((short) 0);
        out.put(multicastAddress);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.length);
        for(byte[] sourceAddress : sourceAddresses) {
            out.put(sourceAddress);
        }
    }

    @Override
    public int getLength() {
        return 24 + (sourceAddresses.length * 16);
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        short maximumResponseCode = in.getShort();
        in.getShort(); // RESERVED
        byte[] multicastAddress = new byte[16];
        in.get(multicastAddress);
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            byte[][] sourceAddresses = new byte[numberOfSources][];
            for(int i = 0; i < sourceAddresses.length; i++) {
                sourceAddresses[i] = new byte[16];
                in.get(sourceAddresses[i]);
            }
            return new MulticastListenerQueryMessage(type, code, maximumResponseCode, multicastAddress, flags, qqic, sourceAddresses);
        } else {
            return new GenericMldMessage(type, code, maximumResponseCode, multicastAddress);
        }
    }

    @Override
    public Icmpv6Type getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public short getMaximumResponseCode() {
        return maximumResponseCode;
    }

    public byte[] getMulticastAddress() {
        return multicastAddress;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getQqic() {
        return qqic;
    }

    public byte[][] getSourceAddresses() {
        return sourceAddresses;
    }
}
