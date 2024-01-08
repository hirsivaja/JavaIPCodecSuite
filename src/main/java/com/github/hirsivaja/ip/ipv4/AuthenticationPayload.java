package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpPayload;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public class AuthenticationPayload implements Ipv4Payload {
    private final Ipv4Header header;
    private final AuthenticationHeader authenticationHeader;
    private final IpPayload authenticatedPayload;

    public AuthenticationPayload(Ipv4Header header, AuthenticationHeader authenticationHeader, IpPayload authenticatedPayload) {
        this.header = header;
        this.authenticationHeader = authenticationHeader;
        this.authenticatedPayload = authenticatedPayload;
    }

    @Override
    public void encode(ByteBuffer out) {
        header.encode(out);
        authenticationHeader.encode(out);
        authenticatedPayload.encode(out);
    }

    @Override
    public int getLength() {
        return header.getLength() + authenticationHeader.getLength() + authenticatedPayload.getLength();
    }

    @Override
    public IpHeader getHeader() {
        return header;
    }

    public static Ipv4Payload decode(ByteBuffer in, Ipv4Header header) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        IpPayload authenticatedPayload = Ipv4Payload.decode(in);
        return new AuthenticationPayload(header, authenticationHeader, authenticatedPayload);
    }

    @Override
    public String toString(){
        return "Authenticated payload " + authenticatedPayload.getLength() + "B (" + authenticatedPayload + ")";
    }

    public AuthenticationHeader getAuthenticationHeader() {
        return authenticationHeader;
    }

    public IpPayload getAuthenticatedPayload() {
        return authenticatedPayload;
    }
}
