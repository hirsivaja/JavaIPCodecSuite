package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpUtils;

import java.nio.ByteBuffer;

public class Ipv4Header implements IpHeader {
    public static final byte VERSION = (byte) 0x04;
    public static final int HEADER_LEN = 20;
    public static final int PSEUDO_HEADER_LEN = 12;
    public static final int VERSION_SHIFT = 4;
    private static final int DSCP_SHIFT = 2;
    private static final int FLAGS_SHIFT = 13;
    private final byte dscp;
    private final EcnCodePoint ecn;
    private final short len;
    private final short identification;
    private final Ipv4Flags flags;
    private final short fragmentOffset;
    private final byte ttl;
    private final IpProtocol protocol;
    private final Ipv4Address srcIp;
    private final Ipv4Address dstIp;
    private final byte[] options;

    @SuppressWarnings("squid:S00107")
    public Ipv4Header(byte dscp, EcnCodePoint ecn, short len, short identification, Ipv4Flags flags, short fragmentOffset, byte ttl,
                      IpProtocol protocol, Ipv4Address srcIp, Ipv4Address dstIp, byte[] options) {
        this.dscp = dscp;
        this.ecn = ecn;
        this.len = len;
        this.identification = identification;
        this.flags = flags;
        this.fragmentOffset = fragmentOffset;
        this.ttl = ttl;
        this.protocol = protocol;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.options = options;
    }

    @Override
    public void encode(ByteBuffer out) {
        byte versionIhl = (byte) (VERSION << VERSION_SHIFT | ((options.length / 4) + 5));
        out.put(versionIhl);
        byte dscpEcn = (byte) (ecn.getType() & 0xFF | (dscp << DSCP_SHIFT));
        out.put(dscpEcn);
        out.putShort(len);
        out.putShort(identification);
        short flagsFragmentOffset = (short) (fragmentOffset | (flags.toByte() << FLAGS_SHIFT));
        out.putShort(flagsFragmentOffset);
        out.put(ttl);
        out.put(protocol.getType());
        int checksumPosition = out.position();
        out.putShort((short) 0);
        srcIp.encode(out);
        dstIp.encode(out);
        out.put(options);
        int position = out.position();
        byte[] headerBytes = new byte[HEADER_LEN];
        out.rewind().get(headerBytes, 0, headerBytes.length);
        short checksum = IpUtils.calculateInternetChecksum(headerBytes);
        out.putShort(checksumPosition, checksum);
        out.position(position);
    }

    @Override
    public byte[] getPseudoHeader() {
        ByteBuffer out = ByteBuffer.allocate(PSEUDO_HEADER_LEN);
        srcIp.encode(out);
        dstIp.encode(out);
        out.put((byte) 0);
        out.put(protocol.getType());
        out.putShort((short) (len - HEADER_LEN - options.length));
        byte[] outBytes = new byte[PSEUDO_HEADER_LEN];
        out.rewind().get(outBytes);
        return outBytes;
    }

    @Override
    public int getLength() {
        return HEADER_LEN + options.length;
    }

    @Override
    public int getPseudoHeaderLength() {
        return PSEUDO_HEADER_LEN;
    }

    public static Ipv4Header decode(ByteBuffer in){
        byte version = in.get();
        byte ihl = (byte) (version & 0x0F);
        version = (byte) (version >>> VERSION_SHIFT);
        if(version != VERSION){
            throw new IllegalArgumentException("Unexpected version for IPv4 header! " + version);
        }
        byte dscp = in.get();
        EcnCodePoint ecn = EcnCodePoint.getType((byte) (dscp & 0b11));
        dscp = (byte) (dscp >>> DSCP_SHIFT);
        short len = in.getShort();
        short identification = in.getShort();
        short fragmentOffset = in.getShort();
        Ipv4Flags flags = Ipv4Flags.decode((byte) (fragmentOffset >>> FLAGS_SHIFT));
        fragmentOffset = (short) (fragmentOffset & 0x1FFF);
        byte ttl = in.get();
        IpProtocol protocol = IpProtocol.getType(in.get());
        in.getShort(); // Checksum not checked
        Ipv4Address srcIp = Ipv4Address.decode(in);
        Ipv4Address dstIp = Ipv4Address.decode(in);
        byte[] options = new byte[(ihl - 5) * 4];
        in.get(options);
        return new Ipv4Header(dscp, ecn, len, identification, flags, fragmentOffset, ttl, protocol,
                srcIp, dstIp, options);
    }

    public byte getDscp() {
        return dscp;
    }

    public EcnCodePoint getEcn() {
        return ecn;
    }

    public int getDataLength() {
        return Short.toUnsignedInt(len);
    }

    public short getIdentification() {
        return identification;
    }

    public Ipv4Flags getFlags() {
        return flags;
    }

    public short getFragmentOffset() {
        return fragmentOffset;
    }

    public byte getTtl() {
        return ttl;
    }

    public IpProtocol getProtocol() {
        return protocol;
    }

    public Ipv4Address getSrcIp() {
        return srcIp;
    }

    public Ipv4Address getDstIp() {
        return dstIp;
    }

    public byte[] getOptions() {
        return options;
    }
}
