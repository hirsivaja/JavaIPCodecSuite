package com.github.hirsivaja.ip.ipv6;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipv6.extension.ExtensionHeader;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Ipv6Header implements IpHeader {
    public static final byte VERSION = (byte) 0x06;
    public static final int HEADER_LEN = 40;
    private static final int VERSION_SHIFT = 28;
    private static final int TRAFFIC_CLASS_MASK = 0xFF00000;
    private static final int TRAFFIC_CLASS_SHIFT = 20;
    private static final int DSCP_SHIFT = 2;
    private static final int FLOW_LABEL_MASK = 0xFFFFF;

    private final byte dscp;
    private final EcnCodePoint ecn;
    private final int flowLabel;
    private final short payloadLength;
    private final IpProtocol nextHeader;
    private final byte hopLimit;
    private final Ipv6Address sourceAddress;
    private final Ipv6Address destinationAddress;
    private final List<ExtensionHeader> extensionHeaders;

    @SuppressWarnings("squid:S00107")
    public Ipv6Header(byte dscp, EcnCodePoint ecn, int flowLabel, short payloadLength, IpProtocol nextHeader, byte hopLimit,
                      Ipv6Address sourceAddress, Ipv6Address destinationAddress) {
        this(dscp, ecn, flowLabel, payloadLength, nextHeader, hopLimit, sourceAddress, destinationAddress, new ArrayList<>());
    }

    @SuppressWarnings("squid:S00107")
    public Ipv6Header(byte dscp, EcnCodePoint ecn, int flowLabel, short payloadLength, IpProtocol nextHeader, byte hopLimit,
                      Ipv6Address sourceAddress, Ipv6Address destinationAddress, List<ExtensionHeader> extensionHeaders) {
        this.dscp = dscp;
        this.ecn = ecn;
        this.flowLabel = flowLabel;
        this.nextHeader = nextHeader;
        this.hopLimit = hopLimit;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.extensionHeaders = extensionHeaders;
        this.payloadLength = (short) (payloadLength + getExtensionsLength());
    }

    @Override
    public byte[] getPseudoHeader(){
        ByteBuffer out = ByteBuffer.allocate(HEADER_LEN);
        sourceAddress.encode(out);
        destinationAddress.encode(out);
        out.putInt(payloadLength - getExtensionsLength());
        out.put((byte) 0);
        out.put((byte) 0);
        out.put((byte) 0);
        out.put(getLastNextHeader().getType());
        byte[] outBytes = new byte[HEADER_LEN];
        out.rewind().get(outBytes);
        return outBytes;
    }

    public void encode(ByteBuffer out){
        byte trafficClass = (byte) (ecn.getType() & 0xFF | (dscp << DSCP_SHIFT));
        int start = 0;
        start |= (VERSION << VERSION_SHIFT);
        start |= (trafficClass << TRAFFIC_CLASS_SHIFT) & TRAFFIC_CLASS_MASK;
        start |= flowLabel & FLOW_LABEL_MASK;
        out.putInt(start);
        out.putShort(payloadLength);
        out.put(nextHeader.getType());
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
        EcnCodePoint ecn = EcnCodePoint.getType((byte) (dscp & 0b11));
        dscp = (byte) (dscp >>> DSCP_SHIFT);
        int flowLabel = start & FLOW_LABEL_MASK;
        short payloadLength = in.getShort();
        IpProtocol nextHeader = IpProtocol.getType(in.get());
        byte hopLimit = in.get();
        Ipv6Address sourceAddress = Ipv6Address.decode(in);
        Ipv6Address destinationAddress = Ipv6Address.decode(in);
        List<ExtensionHeader> extensionHeaders = new ArrayList<>();
        IpProtocol extensionHeaderId = nextHeader;
        while(Ipv6Payload.isExtension(extensionHeaderId)) {
            ExtensionHeader extensionHeader = ExtensionHeader.decode(in, extensionHeaderId);
            extensionHeaders.add(extensionHeader);
            extensionHeaderId = extensionHeader.getNextHeader();
        }
        return new Ipv6Header(dscp, ecn, flowLabel, (short) (payloadLength - getExtensionsLength(extensionHeaders)),
                nextHeader, hopLimit, sourceAddress, destinationAddress, extensionHeaders);
    }

    public IpProtocol getLastNextHeader() {
        if(extensionHeaders.isEmpty()){
            return nextHeader;
        } else {
            return extensionHeaders.get(extensionHeaders.size() - 1).getNextHeader();
        }
    }

    public byte getDscp() {
        return dscp;
    }

    public EcnCodePoint getEcn() {
        return ecn;
    }

    public int getFlowLabel() {
        return flowLabel;
    }

    public int getTotalLength() {
        return Short.toUnsignedInt(payloadLength) + HEADER_LEN;
    }

    public int getPayloadLength() {
        return Short.toUnsignedInt(payloadLength) - getExtensionsLength();
    }

    public IpProtocol getNextHeader() {
        return nextHeader;
    }

    public byte getHopLimit() {
        return hopLimit;
    }

    public Ipv6Address getSourceAddress() {
        return sourceAddress;
    }

    public Ipv6Address getDestinationAddress() {
        return destinationAddress;
    }

    public List<ExtensionHeader> getExtensionHeaders() {
        return extensionHeaders;
    }

    public int getLength() {
        return Ipv6Header.HEADER_LEN + getExtensionsLength();
    }

    @Override
    public int getPseudoHeaderLength() {
        return HEADER_LEN;
    }

    public short getExtensionsLength() {
        return getExtensionsLength(extensionHeaders);
    }

    private static short getExtensionsLength(List<ExtensionHeader> extensions) {
        if(extensions == null){
            return 0;
        }
        return (short) extensions.stream().mapToInt(ExtensionHeader::getLength).sum();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(" +
                "dscp=" + dscp +
                ", ecn=" + ecn +
                ", flowLabel=" + flowLabel +
                ", nextHeader=" + nextHeader +
                ", hopLimit=" + hopLimit +
                ", sourceAddress=" + sourceAddress +
                ", destinationAddress=" + destinationAddress +
                ", extensionHeaders=" + extensionHeaders.size() +
                ")";
    }
}
