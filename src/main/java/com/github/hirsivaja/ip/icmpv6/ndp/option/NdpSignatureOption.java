package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record NdpSignatureOption(ByteArray digitalSignature) implements NdpOption {

    public NdpSignatureOption(byte[] digitalSignature) {
        this(new ByteArray(digitalSignature));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) digitalSignature.length());
        out.putInt(0); // RESERVED
        out.put(digitalSignature.array());
        out.put(new byte[paddingLen()]);
    }

    @Override
    public int length() {
        return 8 + digitalSignature.length() + paddingLen();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.NDP_SIGNATURE;
    }

    public static NdpSignatureOption decode(ByteBuffer in){
        short signatureLength = (short) (in.getShort() & 0x07FF);
        in.getInt(); // RESERVED
        byte[] digitalSignature = new byte[signatureLength];
        in.get(digitalSignature);
        byte[] padding = new byte[in.remaining()];
        in.get(padding);
        return new NdpSignatureOption(digitalSignature);
    }

    private byte paddingLen() {
        return (byte) (8 - (7 + digitalSignature.length()) % 8);
    }
}
