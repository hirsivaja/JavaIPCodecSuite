package com.github.hirsivaja.ip.icmpv6.rpl.security;

import java.nio.ByteBuffer;

public record RplKeyIdentifier(
        boolean hasKeySource,
        boolean hasKeyIndex,
        long keySource,
        byte keyIndex) {

    public RplKeyIdentifier() {
        this(false, false, 0, (byte) 0);
    }

    public RplKeyIdentifier(byte keyIndex) {
        this(false, true, 0, keyIndex);
    }

    public RplKeyIdentifier(long keySource, byte keyIndex) {
        this(true, true, keySource, keyIndex);
    }

    public void encode(ByteBuffer out) {
        if(hasKeySource) {
            out.putLong(keySource);
        }
        if(hasKeyIndex) {
            out.put(keyIndex);
        }
    }

    public int length() {
        int length = 0;
        if(hasKeySource) {
            length += 8;
        }
        if(hasKeyIndex) {
            length += 1;
        }
        return length;
    }

    public static RplKeyIdentifier decode(ByteBuffer in,RplSecurityMode securityMode, RplSecurityLevel securityLevel) {
        boolean hasKeySource = false;
        boolean hasKeyIndex = false;
        switch (securityMode) {
            case GROUP_KEY:
                hasKeyIndex = true;
                break;
            case GROUP_KEY_WITH_SOURCE:
                hasKeySource = true;
                hasKeyIndex = true;
                break;
            case NODE_SIGNATURE_KEY:
                if(securityLevel.isEncrypted()) {
                    hasKeySource = true;
                    hasKeyIndex = true;
                }
                break;
            case PER_PAIR_KEY:
            default:
                break;
        }
        if(hasKeySource) {
            return new RplKeyIdentifier(in.getLong(), in.get());
        } else if(hasKeyIndex) {
            return new RplKeyIdentifier(in.get());
        } else {
            return new RplKeyIdentifier();
        }
    }
}
