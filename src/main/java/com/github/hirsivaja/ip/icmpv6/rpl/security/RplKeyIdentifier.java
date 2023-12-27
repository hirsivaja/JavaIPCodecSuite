package com.github.hirsivaja.ip.icmpv6.rpl.security;

import java.nio.ByteBuffer;

public class RplKeyIdentifier {
    private final boolean hasKeySource;
    private final boolean hasKeyIndex;
    private final long keySource;
    private final byte keyIndex;

    public RplKeyIdentifier() {
        this.hasKeySource = false;
        this.hasKeyIndex = false;
        this.keySource = 0;
        this.keyIndex = 0;
    }

    public RplKeyIdentifier(byte keyIndex) {
        this.hasKeySource = false;
        this.hasKeyIndex = true;
        this.keySource = 0;
        this.keyIndex = keyIndex;
    }

    public RplKeyIdentifier(long keySource, byte keyIndex) {
        this.hasKeySource = true;
        this.hasKeyIndex = true;
        this.keySource = keySource;
        this.keyIndex = keyIndex;
    }

    public void encode(ByteBuffer out) {
        if(hasKeySource) {
            out.putLong(keySource);
        }
        if(hasKeyIndex) {
            out.put(keyIndex);
        }
    }

    public int getLength() {
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

    public boolean hasKeySource() {
        return hasKeySource;
    }

    public boolean hasKeyIndex() {
        return hasKeyIndex;
    }

    public long getKeySource() {
        return keySource;
    }

    public byte getKeyIndex() {
        return keyIndex;
    }
}
