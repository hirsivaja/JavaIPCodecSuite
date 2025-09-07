package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public record AuthenticationPayload(
        Ipv4Header header,
        AuthenticationHeader authenticationHeader,
        IpPayload authenticatedPayload) implements Ipv4Payload {

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        authenticationHeader.encode(out);
        authenticatedPayload.encode(out);
    }

    @Override
    public int length() {
        return header.length() + authenticationHeader.length() + authenticatedPayload.length();
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        IpPayload authenticatedPayload = Ipv4Payload.decode(in);
        return new AuthenticationPayload(header, authenticationHeader, authenticatedPayload);
    }
}
