package com.github.hirsivaja.ip.tcp;

import com.github.hirsivaja.ip.ByteArray;

import java.nio.ByteBuffer;

public record TcpSegment(TcpHeader tcpHeader, ByteArray data) {

    public TcpSegment(TcpHeader tcpHeader, byte[] data) {
        this(tcpHeader, new ByteArray(data));
    }

    public void encode(ByteBuffer out) {
        tcpHeader.encode(out);
        out.put(data.array());
    }

    public int length() {
        return TcpHeader.TCP_HEADER_LEN + data.length();
    }

    public static TcpSegment decode(ByteBuffer in) {
        TcpHeader tcpHeader = TcpHeader.decode(in);
        byte[] data = new byte[in.remaining()];
        in.get(data);
        return new TcpSegment(tcpHeader, data);
    }

    public byte[] rawPayload() {
        return data.array();
    }
}
