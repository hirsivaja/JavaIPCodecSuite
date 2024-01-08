package com.github.hirsivaja.ip.icmpv6.mld;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;

import java.nio.ByteBuffer;

public class MulticastListenerQueryMessage implements Icmpv6Message {
    private final Icmpv6Type type;
    private final byte code;
    private final short maximumResponseCode;
    private final Ipv6Address multicastAddress;
    private final byte flags;
    private final byte qqic;
    private final Ipv6Address[] sourceAddresses;

    public MulticastListenerQueryMessage(Icmpv6Type type, byte code, short maximumResponseCode, Ipv6Address multicastAddress,
                                         byte flags, byte qqic, Ipv6Address[] sourceAddresses) {
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
        multicastAddress.encode(out);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.length);
        for(Ipv6Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
    }

    @Override
    public int getLength() {
        return BASE_LEN + 24 + (sourceAddresses.length * 16);
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Type type, byte code) {
        short maximumResponseCode = in.getShort();
        in.getShort(); // RESERVED
        Ipv6Address multicastAddress = Ipv6Address.decode(in);
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            Ipv6Address[] sourceAddresses = new Ipv6Address[numberOfSources];
            for(int i = 0; i < sourceAddresses.length; i++) {
                sourceAddresses[i] = Ipv6Address.decode(in);
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

    public Ipv6Address getMulticastAddress() {
        return multicastAddress;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getQqic() {
        return qqic;
    }

    public Ipv6Address[] getSourceAddresses() {
        return sourceAddresses;
    }
}
