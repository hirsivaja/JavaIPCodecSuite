package com.github.hirsivaja.ip.ipv4;

public record Ipv4Flags(boolean isMoreFragments, boolean isDoNotFragment, boolean isReservedFlag) {
    private static final byte MFR = (byte) 0x04;
    private static final byte DNF = (byte) 0x02;
    private static final byte RES = (byte) 0x01;

    public byte toByte() {
        byte b = 0;
        if(isMoreFragments) {
            b |= MFR;
        }
        if(isDoNotFragment) {
            b |= DNF;
        }
        if(isReservedFlag) {
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
}
