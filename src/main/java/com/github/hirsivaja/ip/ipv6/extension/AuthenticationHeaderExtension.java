package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public class AuthenticationHeaderExtension implements ExtensionHeader {

    private final AuthenticationHeader authenticationHeader;

    public AuthenticationHeaderExtension(AuthenticationHeader authenticationHeader) {
        this.authenticationHeader = authenticationHeader;
    }

    @Override
    public IpProtocol getNextHeader() {
        return authenticationHeader.getNextHeader();
    }

    @Override
    public void encode(ByteBuffer out) {
        authenticationHeader.encode(out);
    }

    @Override
    public int getLength() {
        return authenticationHeader.getLength();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        return new AuthenticationHeaderExtension(authenticationHeader);
    }

    public AuthenticationHeader getAuthenticationHeader() {
        return authenticationHeader;
    }
}
