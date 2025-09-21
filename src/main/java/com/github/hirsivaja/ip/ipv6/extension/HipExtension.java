package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.IpProtocol;

import java.nio.ByteBuffer;

public record HipExtension(
        IpProtocol nextHeader,
        byte packetType,
        byte flags,
        short checksum,
        short controls,
        ByteArray senderHit,
        ByteArray receiverHit,
        ByteArray hipParameters) implements ExtensionHeader {

    public HipExtension(IpProtocol nextHeader, byte packetType, byte flags, short checksum, short controls, byte[] senderHit, byte[] receiverHit, byte[] hipParameters) {
        this(nextHeader, packetType, flags, checksum, controls, new ByteArray(senderHit), new ByteArray(receiverHit), new ByteArray(hipParameters));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) (32 + hipParameters.length() / 8));
        out.put(packetType);
        out.put(flags);
        out.putShort(checksum);
        out.putShort(controls);
        out.put(senderHit.array());
        out.put(receiverHit.array());
        out.put(hipParameters.array());
    }

    @Override
    public int length() {
        return 40 + hipParameters.length();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        return decode(in, true);
    }

    public static ExtensionHeader decode(ByteBuffer in, boolean ensureChecksum) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        int headerLen = Byte.toUnsignedInt(in.get()) * 8;
        byte packetType = in.get();
        byte flags = in.get();
        short checksum = in.getShort();
        if(ensureChecksum) {
            // TODO
        } else {
            // TODO
        }
        short controls = in.getShort();
        byte[] senderHit = new byte[16];
        in.get(senderHit);
        byte[] receiverHit = new byte[16];
        in.get(receiverHit);
        byte[] hipParameters = new byte[headerLen - 32];
        in.get(hipParameters);
        return new HipExtension(nextHeader, packetType, flags, checksum, controls, senderHit, receiverHit, hipParameters);
    }
}
