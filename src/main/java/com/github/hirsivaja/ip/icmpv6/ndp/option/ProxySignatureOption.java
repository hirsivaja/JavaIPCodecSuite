package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record ProxySignatureOption(ByteArray keyHash, ByteArray digitalSignature) implements NdpOption {

    public ProxySignatureOption(byte[] keyHash, byte[] digitalSignature) {
        this(new ByteArray(keyHash), new ByteArray(digitalSignature));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0); // RESERVED
        out.put(keyHash.array());
        out.put(digitalSignature.array());
    }

    @Override
    public int length() {
        return 4 + keyHash.length() + digitalSignature.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.PROXY_SIGNATURE;
    }

    public static ProxySignatureOption decode(ByteBuffer in){
        in.getShort();  // RESERVED
        byte[] keyHash = new byte[16];
        in.get(keyHash);
        byte[] digitalSignature = new byte[in.remaining()];
        in.get(digitalSignature);
        return new ProxySignatureOption(keyHash, digitalSignature);
    }
}
