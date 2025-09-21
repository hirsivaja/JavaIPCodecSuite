package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;

public record DhcpCaptivePortalOption(ByteArray url) implements NdpOption {

    public DhcpCaptivePortalOption(byte[] url) {
        this(new ByteArray(url));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(url.array());
    }

    @Override
    public int length() {
        return 2 + url.length();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.DHCP_CAPTIVE_PORTAL;
    }

    public static DhcpCaptivePortalOption decode(ByteBuffer in){
        byte[] url = new byte[in.remaining()];
        in.get(url);
        return new DhcpCaptivePortalOption(url);
    }
}
