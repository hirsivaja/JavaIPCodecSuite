package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.EcnCodePoint;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipv6.extension.ExtensionHeader;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Ipv6Header(
        byte dscp,
        EcnCodePoint ecn,
        int flowLabel,
        short payloadLength,
        IpProtocol nextHeader,
        byte hopLimit,
        Ipv6Address sourceAddress,
        Ipv6Address destinationAddress,
        List<ExtensionHeader> extensionHeaders) implements IpHeader {
    public static final byte VERSION = (byte) 0x06;
    public static final int HEADER_LEN = 40;
    private static final int VERSION_SHIFT = 28;
    private static final int TRAFFIC_CLASS_MASK = 0xFF00000;
    private static final int TRAFFIC_CLASS_SHIFT = 20;
    private static final int DSCP_SHIFT = 2;
    private static final int FLOW_LABEL_MASK = 0xFFFFF;

    @SuppressWarnings("squid:S00107")
    public Ipv6Header(byte dscp, EcnCodePoint ecn, int flowLabel, short payloadLength, IpProtocol nextHeader, byte hopLimit,
                      Ipv6Address sourceAddress, Ipv6Address destinationAddress) {
        this(dscp, ecn, flowLabel, payloadLength, nextHeader, hopLimit, sourceAddress, destinationAddress, new ArrayList<>());
    }

    @Override
    public byte[] generatePseudoHeader(){
        ByteBuffer out = ByteBuffer.allocate(HEADER_LEN);
        sourceAddress.encode(out);
        destinationAddress.encode(out);
        out.putInt(payloadLength - extensionsLength());
        out.put((byte) 0);
        out.put((byte) 0);
        out.put((byte) 0);
        out.put(lastNextHeader().type());
        byte[] outBytes = new byte[HEADER_LEN];
        out.rewind().get(outBytes);
        return outBytes;
    }

    @Override
    public void encode(ByteBuffer out){
        byte trafficClass = (byte) (ecn.type() & 0xFF | (dscp << DSCP_SHIFT));
        int start = 0;
        start |= (VERSION << VERSION_SHIFT);
        start |= (trafficClass << TRAFFIC_CLASS_SHIFT) & TRAFFIC_CLASS_MASK;
        start |= flowLabel & FLOW_LABEL_MASK;
        out.putInt(start);
        out.putShort(payloadLength);
        out.put(nextHeader.type());
        out.put(hopLimit);
        sourceAddress.encode(out);
        destinationAddress.encode(out);
        for(ExtensionHeader extensionHeader : extensionHeaders) {
            extensionHeader.encode(out);
        }
    }

    public static Ipv6Header decode(ByteBuffer in){
        int start = in.getInt();
        byte version = (byte) (start >>> VERSION_SHIFT);
        if(version != VERSION){
            throw new IllegalArgumentException("Unexpected version for IPv6 header! " + version);
        }
        byte dscp = (byte) ((start & TRAFFIC_CLASS_MASK) >>> TRAFFIC_CLASS_SHIFT);
        EcnCodePoint ecn = EcnCodePoint.fromType((byte) (dscp & 0b11));
        dscp = (byte) (dscp >>> DSCP_SHIFT);
        int flowLabel = start & FLOW_LABEL_MASK;
        short payloadLength = in.getShort();
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        byte hopLimit = in.get();
        Ipv6Address sourceAddress = Ipv6Address.decode(in);
        Ipv6Address destinationAddress = Ipv6Address.decode(in);
        List<ExtensionHeader> extensionHeaders = new ArrayList<>();
        IpProtocol extensionHeaderId = nextHeader;
        while(Ipv6Payload.isExtension(extensionHeaderId)) {
            ExtensionHeader extensionHeader = ExtensionHeader.decode(in, extensionHeaderId);
            extensionHeaders.add(extensionHeader);
            extensionHeaderId = extensionHeader.nextHeader();
        }
        return new Ipv6Header(dscp, ecn, flowLabel, payloadLength, nextHeader, hopLimit, sourceAddress,
                destinationAddress, extensionHeaders);
    }

    public IpProtocol lastNextHeader() {
        if(extensionHeaders.isEmpty()){
            return nextHeader;
        } else {
            return extensionHeaders.getLast().nextHeader();
        }
    }

    /**
     * Header + extensions length (no payload)
     */
    @Override
    public int length() {
        return Ipv6Header.HEADER_LEN + extensionsLength();
    }

    /**
     * Payload + extensions length (no header)
     */
    public int dataLength() {
        return Short.toUnsignedInt(payloadLength);
    }

    /**
     * Payload + extensions + header length
     */
    public int totalLength() {
        return Short.toUnsignedInt(payloadLength) + HEADER_LEN;
    }

    /**
     * Payload length (no header or extensions)
     */
    public int payloadOnlyLength() {
        return Short.toUnsignedInt(payloadLength) - extensionsLength();
    }

    @Override
    public int pseudoHeaderLength() {
        return HEADER_LEN;
    }

    public short extensionsLength() {
        return calculateExtensionsLength(extensionHeaders);
    }

    public static short calculateExtensionsLength(List<ExtensionHeader> extensions) {
        if(extensions == null){
            return 0;
        }
        return (short) extensions.stream().mapToInt(ExtensionHeader::length).sum();
    }
}
