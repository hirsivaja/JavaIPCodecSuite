package com.github.hirsivaja.ip.ipv4.option;

import java.nio.ByteBuffer;

public record QuickStart(byte functionAndRateRequest, byte qsTtl, int qsNonce) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() - 2));
        out.put(functionAndRateRequest);
        out.put(qsTtl);
        out.putInt(qsNonce);
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.QUICK_START;
    }

    public static IpOption decode(ByteBuffer in) {
        byte functionAndRateRequest = in.get();
        byte qsTtl = in.get();
        int qsNonce = in.getInt();
        return new QuickStart(functionAndRateRequest, qsTtl, qsNonce);
    }
}
