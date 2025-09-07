package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public record FragmentationExtension(
        IpProtocol nextHeader,
        short fragmentOffset,
        boolean isMoreFragments,
        int identification) implements ExtensionHeader {

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) 0);
        short fragmentOffsetAndMoreFlag = (short) ((fragmentOffset & 0xFFFF) << 3);
        fragmentOffsetAndMoreFlag = (short) (fragmentOffsetAndMoreFlag | (isMoreFragments ? 1 : 0));
        out.putShort(fragmentOffsetAndMoreFlag);
        out.putInt(identification);
    }

    @Override
    public int length() {
        return 8;
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        in.get(); // RESERVED
        short fragmentOffsetAndMoreFlag = in.getShort();
        short fragmentOffset = (short) ((fragmentOffsetAndMoreFlag & 0xFFFF) >> 3);
        boolean moreFragments = (fragmentOffsetAndMoreFlag & 1) > 0;
        int identification = in.getInt();
        return new FragmentationExtension(nextHeader, fragmentOffset, moreFragments, identification);
    }
}
