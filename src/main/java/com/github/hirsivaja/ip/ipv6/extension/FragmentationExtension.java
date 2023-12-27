package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public class FragmentationExtension implements ExtensionHeader {
    private final IpProtocol nextHeader;
    private final short fragmentOffset;
    private final boolean moreFragments;
    private final int identification;

    public FragmentationExtension(IpProtocol nextHeader, short fragmentOffset, boolean moreFragments,
                                  int identification) {
        this.nextHeader = nextHeader;
        this.fragmentOffset = fragmentOffset;
        this.moreFragments = moreFragments;
        this.identification = identification;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.getType());
        out.put((byte) 0);
        short fragmentOffsetAndMoreFlag = (short) ((fragmentOffset & 0xFFFF) << 3);
        fragmentOffsetAndMoreFlag = (short) (fragmentOffsetAndMoreFlag | (moreFragments ? 1 : 0));
        out.putShort(fragmentOffsetAndMoreFlag);
        out.putInt(identification);
    }

    @Override
    public int getLength() {
        return 8;
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.getType(in.get());
        in.get(); // RESERVED
        short fragmentOffsetAndMoreFlag = in.getShort();
        short fragmentOffset = (short) ((fragmentOffsetAndMoreFlag & 0xFFFF) >> 3);
        boolean moreFragments = (fragmentOffsetAndMoreFlag & 1) > 0;
        int identification = in.getInt();
        return new FragmentationExtension(nextHeader, fragmentOffset, moreFragments, identification);
    }

    @Override
    public IpProtocol getNextHeader() {
        return nextHeader;
    }

    public short getFragmentOffset() {
        return fragmentOffset;
    }

    public boolean isMoreFragments() {
        return moreFragments;
    }

    public int getIdentification() {
        return identification;
    }
}
