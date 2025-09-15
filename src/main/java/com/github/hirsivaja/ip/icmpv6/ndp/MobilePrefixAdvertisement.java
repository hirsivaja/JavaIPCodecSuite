package com.github.hirsivaja.ip.icmpv6.ndp;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;
import com.github.hirsivaja.ip.icmpv6.ndp.option.NdpOption;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MobilePrefixAdvertisement(short identifier, boolean mFlag, boolean oFlag, List<NdpOption> options) implements Icmpv6Message {
    private static final int MO = 0xC000;
    private static final int M = 0x8000;
    private static final int O = 0x4000;

    @Override
    public void encode(ByteBuffer out) {
        out.putShort(identifier);
        if(mFlag && oFlag) {
            out.putShort((short) MO);
        } else if(mFlag) {
            out.putShort((short) M);
        } else if(oFlag) {
            out.putShort((short) O);
        } else {
            out.putShort((short) 0);
        }
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return BASE_LEN + 4 + options.stream().mapToInt(NdpOption::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in) {
        short identifier = in.getShort();
        short reserved = in.getShort(); // RESERVED
        boolean mFlag = false;
        boolean oFlag = false;
        switch (reserved & MO) {
            case MO -> {
                mFlag = true;
                oFlag = true;
            }
            case M -> mFlag = true;
            case O -> oFlag = true;
            default -> {/* BOTH FLAGS FALSE */}
        }
        List<NdpOption> options = new ArrayList<>();
        while(in.remaining() > 2) {
            options.add(NdpOption.decode(in));
        }
        return new MobilePrefixAdvertisement(identifier, mFlag, oFlag, options);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.MOBILE_PREFIX_ADVERTISEMENT;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.MOBILE_PREFIX_ADVERTISEMENT;
    }
}
