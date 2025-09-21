package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;

public record AddressRegistrationOption(byte status, short registrationLifetime, long eui64) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(status);
        out.put((byte) 0); // RESERVED
        out.putShort((short) 0); // RESERVED
        out.putShort(registrationLifetime);
        out.putLong(eui64);
    }

    @Override
    public int length() {
        return 16;
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.ADDRESS_REGISTRATION;
    }

    public static AddressRegistrationOption decode(ByteBuffer in){
        byte status = in.get();
        in.get(); // RESERVED
        in.getShort(); // RESERVED
        short registrationLifetime = in.getShort();
        long eui64 = in.getLong();
        return new AddressRegistrationOption(status, registrationLifetime, eui64);
    }
}
