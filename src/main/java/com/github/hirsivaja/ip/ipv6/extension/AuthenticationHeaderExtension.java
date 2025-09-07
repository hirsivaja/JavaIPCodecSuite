package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipsec.AuthenticationHeader;

import java.nio.ByteBuffer;

public record AuthenticationHeaderExtension(AuthenticationHeader authenticationHeader) implements ExtensionHeader {

    @Override
    public IpProtocol nextHeader() {
        return authenticationHeader.nextHeader();
    }

    @Override
    public void encode(ByteBuffer out) {
        authenticationHeader.encode(out);
    }

    @Override
    public int length() {
        return authenticationHeader.length();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        AuthenticationHeader authenticationHeader = AuthenticationHeader.decode(in);
        return new AuthenticationHeaderExtension(authenticationHeader);
    }
}
