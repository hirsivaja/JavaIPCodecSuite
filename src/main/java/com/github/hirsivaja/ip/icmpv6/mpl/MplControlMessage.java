package com.github.hirsivaja.ip.icmpv6.mpl;

import com.github.hirsivaja.ip.icmpv6.Icmpv6Code;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Codes;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Message;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Type;
import com.github.hirsivaja.ip.icmpv6.Icmpv6Types;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record MplControlMessage(List<MplSeedInfo> mplSeedInfos) implements Icmpv6Message {

    @Override
    public void encode(ByteBuffer out) {
        mplSeedInfos.forEach(mplSeedInfo -> mplSeedInfo.encode(out));
    }

    @Override
    public int length() {
        return BASE_LEN + mplSeedInfos.stream().mapToInt(MplSeedInfo::length).sum();
    }

    public static Icmpv6Message decode(ByteBuffer in, Icmpv6Code code) {
        List<MplSeedInfo> mplSeedInfos = new ArrayList<>();
        while(in.hasRemaining()) {
            mplSeedInfos.add(MplSeedInfo.decode(in));
        }
        return new MplControlMessage(mplSeedInfos);
    }

    @Override
    public Icmpv6Type type() {
        return Icmpv6Types.MPL_CONTROL_MESSAGE;
    }

    @Override
    public Icmpv6Code code() {
        return Icmpv6Codes.MPL_CONTROL_MESSAGE;
    }
}
