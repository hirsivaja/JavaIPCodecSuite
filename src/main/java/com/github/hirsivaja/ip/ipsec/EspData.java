package com.github.hirsivaja.ip.ipsec;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;
import java.util.Arrays;

public record EspData(EspPayload payload, IpProtocol nextHeader, ByteArray icv, ByteArray encryptedData) {
    
    public EspData(EspPayload payload, IpProtocol nextHeader, byte[] icv, byte[] encryptedData) {
        this(payload, nextHeader, new ByteArray(icv), new ByteArray(encryptedData));
    }

    public static EspData fromEspPayload(EspPayload payload, int icvLength) {
        ByteBuffer in = ByteBuffer.wrap(payload.rawData());
        byte[] encryptedDataAndPadding = new byte[payload.data().length() - 2 - icvLength];
        in.get(encryptedDataAndPadding);
        int paddingLen = Byte.toUnsignedInt(in.get());
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        byte[] icv = new byte[icvLength];
        in.get(icv);
        byte[] encryptedData = Arrays.copyOfRange(encryptedDataAndPadding, 0, encryptedDataAndPadding.length - paddingLen);
        return new EspData(payload, nextHeader, icv, encryptedData);
    }

    public byte[] rawEncryptedData() {
        return encryptedData.array();
    }

    public byte[] rawIcv() {
        return icv.array();
    }
}
