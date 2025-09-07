package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record MtuOption(int mtu) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) 1);
        out.putShort((short) 0);
        out.putInt(mtu);
    }

    @Override
    public int length() {
        return 8;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.MTU;
    }

    public static MtuOption decode(ByteBuffer in){
        in.get(); // LEN
        in.getShort(); // RESERVED
        int mtu = in.getInt();
        return new MtuOption(mtu);
    }
}
