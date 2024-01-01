package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;

public class MembershipQueryMessage implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final Ipv4Address groupAddress;
    private final byte flags;
    private final byte qqic;
    private final Ipv4Address[] sourceAddresses;

    public MembershipQueryMessage(IgmpType type, byte code, Ipv4Address groupAddress, byte flags, byte qqic,
                                  Ipv4Address[] sourceAddresses) {
        this.type = type;
        this.code = code;
        this.groupAddress = groupAddress;
        this.flags = flags;
        this.qqic = qqic;
        this.sourceAddresses = sourceAddresses;
    }

    @Override
    public void encode(ByteBuffer out) {
        groupAddress.encode(out);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.length);
        for(Ipv4Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
    }

    @Override
    public int getLength() {
        return 8 + (sourceAddresses.length * 4);
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            Ipv4Address[] sourceAddresses = new Ipv4Address[numberOfSources];
            for(int i = 0; i < sourceAddresses.length; i++) {
                sourceAddresses[i] = Ipv4Address.decode(in);
            }
            return new MembershipQueryMessage(type, code, groupAddress, flags, qqic, sourceAddresses);
        } else {
            if(code == 0) {
                return new GenericIgmpV1Message(type, code, groupAddress);
            } else {
                return new GenericIgmpV2Message(type, code, groupAddress);
            }
        }
    }

    @Override
    public IgmpType getType() {
        return type;
    }

    @Override
    public byte getCode() {
        return code;
    }

    public byte getMaxRespCode() {
        return getCode();
    }

    public Ipv4Address getGroupAddress() {
        return groupAddress;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getQqic() {
        return qqic;
    }

    public Ipv4Address[] getSourceAddresses() {
        return sourceAddresses;
    }
}
