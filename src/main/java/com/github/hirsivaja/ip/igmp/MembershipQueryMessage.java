package com.github.hirsivaja.ip.igmp;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MembershipQueryMessage(
        IgmpType type,
        byte code,
        Ipv4Address groupAddress,
        byte flags,
        byte qqic,
        List<Ipv4Address> sourceAddresses) implements IgmpMessage {

    @Override
    public void encode(ByteBuffer out) {
        groupAddress.encode(out);
        out.put(flags);
        out.put(qqic);
        out.putShort((short) sourceAddresses.size());
        for(Ipv4Address sourceAddress : sourceAddresses) {
            sourceAddress.encode(out);
        }
    }

    @Override
    public int length() {
        return BASE_LEN + 8 + (sourceAddresses.size() * 4);
    }

    public static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        Ipv4Address groupAddress = Ipv4Address.decode(in);
        if(in.remaining() >= 4) {
            byte flags = in.get();
            byte qqic = in.get();
            short numberOfSources = in.getShort();
            List<Ipv4Address> sourceAddresses = new ArrayList<>();
            for(int i = 0; i < numberOfSources; i++) {
                sourceAddresses.add(Ipv4Address.decode(in));
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

    public byte maxRespCode() {
        return code();
    }
}
