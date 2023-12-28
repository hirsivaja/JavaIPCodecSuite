package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public class MtuOption implements NdpOption {
    private final int mtu;

    public MtuOption(int mtu) {
        this.mtu = mtu;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(getOptionType().getType());
        out.put((byte) 1);
        out.putShort((short) 0);
        out.putInt(mtu);
    }

    @Override
    public int getLength() {
        return 8;
    }

    @Override
    public NdpOptionType getOptionType() {
        return NdpOptionType.MTU;
    }

    public static MtuOption decode(ByteBuffer in){
        in.get(); // LEN
        in.getShort(); // RESERVED
        int mtu = in.getInt();
        return new MtuOption(mtu);
    }

    public int getMtu() {
        return mtu;
    }
}
