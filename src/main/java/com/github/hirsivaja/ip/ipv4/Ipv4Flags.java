package com.github.hirsivaja.ip.ipv4;

public class Ipv4Flags {
    private static final byte MFR = (byte) 0x04;
    private static final byte DNF = (byte) 0x02;
    private static final byte RES = (byte) 0x01;
    private final boolean moreFragments;
    private final boolean doNotFragment;
    private final boolean reservedFlag;

    public Ipv4Flags(boolean moreFragments, boolean doNotFragment, boolean reservedFlag) {
        this.moreFragments = moreFragments;
        this.doNotFragment = doNotFragment;
        this.reservedFlag = reservedFlag;
    }

    public byte toByte() {
        byte b = 0;
        if(moreFragments) {
            b |= MFR;
        }
        if(doNotFragment) {
            b |= DNF;
        }
        if(reservedFlag) {
            b |= RES;
        }
        return b;
    }

    public static Ipv4Flags decode(byte flags) {
        boolean moreFragments = (flags & MFR & 0xFF) > 0;
        boolean doNotFragment = (flags & DNF & 0xFF) > 0;
        boolean reservedFlag = (flags & RES & 0xFF) > 0;
        return new Ipv4Flags(moreFragments, doNotFragment, reservedFlag);
    }

    public boolean isMoreFragments() {
        return moreFragments;
    }

    public boolean isDoNotFragment() {
        return doNotFragment;
    }

    public boolean isReservedFlag() {
        return reservedFlag;
    }
}
