package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipv6.extension.mobility.MobilityMessage;
import com.github.hirsivaja.ip.ipv6.extension.mobility.MobilityMessageType;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

public record MobilityHeaderExtension(
        IpProtocol nextHeader,
        short checksum,
        MobilityMessage mobilityMessage) implements ExtensionHeader {
    private static final Logger logger = Logger.getLogger("MobilityHeaderExtension");

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) (length() / 8 - 1));
        out.put(mobilityMessage.type().type());
        out.put((byte) 0); // RESERVED
        out.putShort(checksum);
        mobilityMessage.encode(out);
    }

    @Override
    public int length() {
        return 6 + mobilityMessage.length();
    }
    public static ExtensionHeader decode(ByteBuffer in) {
        return decode(in, true);
    }

    public static ExtensionHeader decode(ByteBuffer in, boolean ensureChecksum) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        int headerLen = Byte.toUnsignedInt(in.get()) * 8;
        MobilityMessageType mobilityMessageType = MobilityMessageType.fromType(in.get());
        in.get(); // RESERVED
        short checksum = in.getShort();
        if(ensureChecksum) {
            logger.warning("Checksum verification for MobilityHeaderExtension is not implemented!");
        } else {
            logger.finer("Skipped checksum verification for MobilityHeaderExtension!");
        }
        byte[] messageBytes = new byte[headerLen + 2];
        in.get(messageBytes);
        ByteBuffer messageBuffer = ByteBuffer.wrap(messageBytes);
        MobilityMessage mobilityMessage = MobilityMessage.decode(messageBuffer, mobilityMessageType);
        return new MobilityHeaderExtension(nextHeader, checksum, mobilityMessage);
    }
}
