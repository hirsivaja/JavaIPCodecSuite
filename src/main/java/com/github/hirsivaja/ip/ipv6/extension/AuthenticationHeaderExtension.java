package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public class AuthenticationHeaderExtension implements ExtensionHeader {

    private final IpProtocol nextHeader;
    private final int spi;
    private final int seqNumber;
    private final byte[] icv;

    public AuthenticationHeaderExtension(IpProtocol nextHeader, int spi, int seqNumber, byte[] icv) {
        this.nextHeader = nextHeader;
        this.spi = spi;
        this.seqNumber = seqNumber;
        this.icv = icv;
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.getType());
        out.put((byte) (icv.length / 4 + 1));
        out.putShort((short) 0);
        out.putInt(spi);
        out.putInt(seqNumber);
        out.put(icv);
    }

    @Override
    public int getLength() {
        return 12 + icv.length;
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.getType(in.get());
        int payloadLen = Byte.toUnsignedInt(in.get()) * 4;
        in.getShort(); // RESERVED
        int spi = in.getInt();
        int seqNumber = in.getInt();
        byte[] icv = new byte[payloadLen - 4];
        in.get(icv);
        return new AuthenticationHeaderExtension(nextHeader, spi, seqNumber, icv);
    }

    public IpProtocol getNextHeader() {
        return nextHeader;
    }

    public int getSpi() {
        return spi;
    }

    public int getSeqNumber() {
        return seqNumber;
    }

    public byte[] getIcv() {
        return icv;
    }
}
