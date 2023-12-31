package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public class MembershipQueryMessage implements IgmpMessage {
    private final IgmpType type;
    private final byte code;
    private final int groupAddress;
    private final byte flags;
    private final byte qqic;
    private final int[] sourceAddresses;

    public MembershipQueryMessage(IgmpType type, byte code, int groupAddress, byte flags, byte qqic,
                                  int[] sourceAddresses) {
        this.type = type;
        this.code = code;
        this.groupAddress = groupAddress;
        this.flags = flags;
        this.qqic = qqic;
        this.sourceAddresses = sourceAddresses;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.putInt(groupAddress);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.length);
        for(int sourceAddress : sourceAddresses) {
            out.putInt(sourceAddress);
        }
    }

    @Override
    public int getLength() {
        return 8 + (sourceAddresses.length * 4);
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        int groupAddress = in.getInt();
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            int[] sourceAddresses = new int[numberOfSources];
            for(int i = 0; i < sourceAddresses.length; i++) {
                sourceAddresses[i] = in.getInt();
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

    public int getGroupAddress() {
        return groupAddress;
    }

    public byte getFlags() {
        return flags;
    }

    public byte getQqic() {
        return qqic;
    }

    public int[] getSourceAddresses() {
        return sourceAddresses;
    }
}
