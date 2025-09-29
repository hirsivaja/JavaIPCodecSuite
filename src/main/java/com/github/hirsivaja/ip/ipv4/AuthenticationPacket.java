package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPacket;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public record AuthenticationPacket(
        Ipv4Header header,
        AuthenticationHeader authenticationHeader,
        IpPacket authenticatedPacket) implements Ipv4Packet {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        authenticationHeader.encode(out);
        authenticatedPacket.encode(out);
    }

    @Override
    public int length() {
        return header.length() + authenticationHeader.length() + authenticatedPacket.length();
    }

    public static Ipv4Packet decode(ByteBuffer in, Ipv4Header header) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        IpPacket authenticatedPacket = Ipv4Packet.decode(in);
        return new AuthenticationPacket(header, authenticationHeader, authenticatedPacket);
    }
}
