package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record CertificateOption(byte certificateType, ByteArray certificateAndPadding) implements NdpOption {

    public CertificateOption(byte certificateType, byte[] certificateAndPadding) {
        this(certificateType, new ByteArray(certificateAndPadding));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(certificateType);
        out.put((byte) 0);
        out.put(certificateAndPadding.array());
    }

    @Override
    public int length() {
        return 4 + certificateAndPadding.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.CERTIFICATE;
    }

    public static CertificateOption decode(ByteBuffer in){
        int length = in.get() * 8;
        byte certificateType = in.get();
        in.get(); // RESERVED
        byte[] certificateAndPadding = new byte[length - 4];
        in.get(certificateAndPadding);
        return new CertificateOption(certificateType, certificateAndPadding);
    }
}
