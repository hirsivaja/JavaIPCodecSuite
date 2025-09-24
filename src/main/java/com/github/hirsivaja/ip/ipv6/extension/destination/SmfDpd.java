package com.github.hirsivaja.ip.ipv6.extension.destination;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record SmfDpd(
        byte tidTypeAndLen,
        ByteArray taggerId,
        ByteArray identifier,
        ByteArray hav) implements DestinationOption {

    public SmfDpd(byte[] hav) {
        this((byte) 0, null, null, new ByteArray(hav));
    }

    public SmfDpd(byte tidTypeAndLen, byte[] taggerId, byte[] identifier) {
        this(tidTypeAndLen, new ByteArray(taggerId), new ByteArray(identifier), null);
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        if(hav == null) {
            out.put(tidTypeAndLen);
            out.put(taggerId.array());
            out.put(identifier.array());
        } else {
            out.put(hav.array());
        }
    }

    @Override
    public int length() {
        if(hav == null) {
            return 3 + taggerId.length() + identifier.length();
        } else {
            return 2 + hav.length();
        }
    }

    @Override
    public DestinationOptionType optionType() {
        return DestinationOptionType.SMF_DPD;
    }

    public static DestinationOption decode(ByteBuffer in) {
        byte tidTypeAndLen = in.get();
        if((tidTypeAndLen & 0x80) == 0) {
            int tidLen = tidTypeAndLen & 0x0F;
            byte[] taggerId = new byte[tidLen];
            in.get(taggerId);
            byte[] identifier = new byte[in.remaining()];
            in.get(identifier);
            return new SmfDpd(tidTypeAndLen, taggerId, identifier);
        } else {
            byte[] havTail = new byte[in.remaining()];
            in.get(havTail);
            byte[] hav = new byte[havTail.length + 1];
            hav[0] = tidTypeAndLen;
            System.arraycopy(havTail, 0, hav, 1, havTail.length);
            return new SmfDpd(hav);
        }
    }
}
