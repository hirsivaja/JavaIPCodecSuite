package com.github.hirsivaja.ip.tcp.option;

import java.nio.ByteBuffer;

public record UserTimeout(int userTimeout, boolean isInMinutes) implements TcpOption {

    @Override
    public void encode(ByteBuffer out) {
        short timeout = (short) (isInMinutes ? (0x8000 | userTimeout) & 0xFFFF : userTimeout);
        out.put(optionType().type());
        out.put((byte) (length()));
        out.putShort(timeout);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public TcpOptionType optionType() {
        return TcpOptionType.USER_TIMEOUT;
    }

    public static TcpOption decode(ByteBuffer in){
        if(in.remaining() == 2) {
            int userTimeout = Short.toUnsignedInt(in.getShort());
            boolean isInMinutes = userTimeout > 0x7FFF;
            return new UserTimeout(userTimeout & 0x7FFF, isInMinutes);
        } else {
            return GenericTcpOption.decode(in, TcpOptionType.USER_TIMEOUT);
        }
    }
}
