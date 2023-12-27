package com.github.hirsivaja.ip.icmpv6.rpl.security;

import java.nio.ByteBuffer;

public class RplSecurity {
    private final boolean counterTypeTime;
    private final byte algorithm;
    private final RplSecurityMode securityMode;
    private final RplSecurityLevel securityLevel;
    private final byte flags;
    private final int counter;
    private final RplKeyIdentifier keyIdentifier;

    public RplSecurity(boolean counterTypeTime, byte algorithm, RplSecurityMode securityMode,
                       RplSecurityLevel securityLevel, byte flags, int counter, RplKeyIdentifier keyIdentifier) {
        this.counterTypeTime = counterTypeTime;
        this.algorithm = algorithm;
        this.securityMode = securityMode;
        this.securityLevel = securityLevel;
        this.flags = flags;
        this.counter = counter;
        this.keyIdentifier = keyIdentifier;
    }

    public void encode(ByteBuffer out) {
        out.put((byte) (counterTypeTime ? 0x80 : 0));
        out.put(algorithm);
        byte modeAndLevel = (byte) ((securityMode.getType() << 6) | (securityLevel.getType() & 0xFF));
        out.put(modeAndLevel);
        out.put(flags);
        out.putInt(counter);
        keyIdentifier.encode(out);
    }

    public int getLength() {
        return 8 + keyIdentifier.getLength();
    }

    public static RplSecurity decode(ByteBuffer in) {
        boolean counterTypeTime = in.get() != 0;
        byte algorithm = in.get();
        byte modeAndLevel = in.get();
        RplSecurityMode securityMode = RplSecurityMode.getRplSecurityMode((byte) ((modeAndLevel & 0xFF) >>> 6));
        RplSecurityLevel securityLevel = RplSecurityLevel.getRplSecurityMode(
                (byte) (modeAndLevel & 0b111), securityMode == RplSecurityMode.NODE_SIGNATURE_KEY);
        byte flags = in.get();
        int counter = in.getInt();
        RplKeyIdentifier keyIdentifier = RplKeyIdentifier.decode(in, securityMode, securityLevel);
        return new RplSecurity(counterTypeTime, algorithm, securityMode, securityLevel, flags, counter, keyIdentifier);
    }

    public boolean isCounterTypeTime() {
        return counterTypeTime;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public RplSecurityMode getSecurityMode() {
        return securityMode;
    }

    public RplSecurityLevel getSecurityLevel() {
        return securityLevel;
    }

    public byte getFlags() {
        return flags;
    }

    public int getCounter() {
        return counter;
    }

    public RplKeyIdentifier getKeyIdentifier() {
        return keyIdentifier;
    }
}
