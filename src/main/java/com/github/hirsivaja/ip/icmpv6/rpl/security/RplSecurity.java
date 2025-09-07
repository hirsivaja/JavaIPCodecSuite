package com.github.hirsivaja.ip.icmpv6.rpl.security;

import java.nio.ByteBuffer;

public record RplSecurity(
        boolean isCounterTypeTime,
        byte algorithm,
        RplSecurityMode securityMode,
        RplSecurityLevel securityLevel,
        byte flags,
        int counter,
        RplKeyIdentifier keyIdentifier) {

    public void encode(ByteBuffer out) {
        out.put((byte) (isCounterTypeTime ? 0x80 : 0));
        out.put(algorithm);
        byte modeAndLevel = (byte) ((securityMode.type() << 6) | (securityLevel.type() & 0xFF));
        out.put(modeAndLevel);
        out.put(flags);
        out.putInt(counter);
        keyIdentifier.encode(out);
    }

    public int length() {
        return 8 + keyIdentifier.length();
    }

    public static RplSecurity decode(ByteBuffer in) {
        boolean counterTypeTime = in.get() != 0;
        byte algorithm = in.get();
        byte modeAndLevel = in.get();
        RplSecurityMode securityMode = RplSecurityMode.fromRplSecurityMode((byte) ((modeAndLevel & 0xFF) >>> 6));
        RplSecurityLevel securityLevel = RplSecurityLevel.fromRplSecurityMode(
                (byte) (modeAndLevel & 0b111), securityMode == RplSecurityMode.NODE_SIGNATURE_KEY);
        byte flags = in.get();
        int counter = in.getInt();
        RplKeyIdentifier keyIdentifier = RplKeyIdentifier.decode(in, securityMode, securityLevel);
        return new RplSecurity(counterTypeTime, algorithm, securityMode, securityLevel, flags, counter, keyIdentifier);
    }
}
