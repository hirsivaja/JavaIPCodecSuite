package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public record AuthenticationPayload(
        AuthenticationHeader authenticationHeader,
        IpPacket authenticatedPacket) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        authenticationHeader.encode(out);
        authenticatedPacket.encode(out);
    }

    @Override
    public int length() {
        return authenticationHeader.length() + authenticatedPacket.length();
    }

    public static AuthenticationPayload decode(ByteBuffer in, boolean ensureChecksum) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        IpPacket authenticatedPacket = Ipv4Packet.decode(in, ensureChecksum);
        return new AuthenticationPayload(authenticationHeader, authenticatedPacket);
    }
}
