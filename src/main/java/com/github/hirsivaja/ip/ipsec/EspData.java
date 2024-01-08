package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class EspData {
    private final EspPayload payload;
    private final byte[] encryptedData;
    private final IpProtocol nextHeader;
    private final byte[] icv;

    public EspData(EspPayload payload, int icvLength) {
        this.payload = payload;
        ByteBuffer in = ByteBuffer.wrap(payload.getData());
        byte[] encryptedDataAndPadding = new byte[payload.getData().length - 2 - icvLength];
        in.get(encryptedDataAndPadding);
        int paddingLen = Byte.toUnsignedInt(in.get());
        this.nextHeader = IpProtocol.getType(in.get());
        this.icv = new byte[icvLength];
        in.get(icv);
        this.encryptedData = Arrays.copyOfRange(encryptedDataAndPadding, 0, encryptedDataAndPadding.length - paddingLen);
    }

    public EspPayload getPayload() {
        return payload;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public IpProtocol getNextHeader() {
        return nextHeader;
    }

    public byte[] getIcv() {
        return icv;
    }
}
