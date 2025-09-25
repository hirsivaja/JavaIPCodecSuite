package com.github.hirsivaja.ip.ipv4;

import com.github.hirsivaja.ip.EcnCodePoint;
import com.github.hirsivaja.ip.IpHeader;
import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.IpUtils;
import com.github.hirsivaja.ip.ipv4.option.IpOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record Ipv4Header(
        byte dscp,
        EcnCodePoint ecn,
        short len,
        short identification,
        Ipv4Flags flags,
        short fragmentOffset,
        byte ttl,
        IpProtocol protocol,
        Ipv4Address srcIp,
        Ipv4Address dstIp,
        List<IpOption> options) implements IpHeader {
    public static final byte VERSION = (byte) 0x04;
    public static final int HEADER_LEN = 20;
    public static final int PSEUDO_HEADER_LEN = 12;
    public static final int VERSION_SHIFT = 4;
    private static final int DSCP_SHIFT = 2;
    private static final int FLAGS_SHIFT = 13;

    @SuppressWarnings("squid:S00107")
    public Ipv4Header(byte dscp, EcnCodePoint ecn, short len, short identification, Ipv4Flags flags, short fragmentOffset, byte ttl,
                      IpProtocol protocol, Ipv4Address srcIp, Ipv4Address dstIp) {
        this(dscp, ecn, len, identification, flags, fragmentOffset, ttl, protocol, srcIp, dstIp, List.of());
    }

    @Override
    public void encode(ByteBuffer out) {
        out.mark();
        byte versionIhl = (byte) (VERSION << VERSION_SHIFT | ((optionsLength() / 4) + 5));
        out.put(versionIhl);
        byte dscpEcn = (byte) (ecn.type() & 0xFF | (dscp << DSCP_SHIFT));
        out.put(dscpEcn);
        out.putShort(len);
        out.putShort(identification);
        short flagsFragmentOffset = (short) (fragmentOffset | (flags.toByte() << FLAGS_SHIFT));
        out.putShort(flagsFragmentOffset);
        out.put(ttl);
        out.put(protocol.type());
        int checksumPosition = out.position();
        out.putShort((short) 0);
        srcIp.encode(out);
        dstIp.encode(out);
        options.forEach(option -> option.encode(out));
        int position = out.position();
        byte[] headerBytes = new byte[HEADER_LEN];
        out.reset().get(headerBytes);
        short checksum = IpUtils.calculateInternetChecksum(headerBytes);
        out.putShort(checksumPosition, checksum);
        out.position(position);
    }

    @Override
    public byte[] generatePseudoHeader() {
        ByteBuffer out = ByteBuffer.allocate(PSEUDO_HEADER_LEN);
        srcIp.encode(out);
        dstIp.encode(out);
        out.put((byte) 0);
        out.put(protocol.type());
        out.putShort((short) (len - HEADER_LEN - optionsLength()));
        byte[] outBytes = new byte[PSEUDO_HEADER_LEN];
        out.rewind().get(outBytes);
        return outBytes;
    }

    /**
     * Header + options length (no payload)
     */
    @Override
    public int length() {
        return HEADER_LEN + optionsLength();
    }

    /**
     * Payload + options length (no header)
     */
    public int dataLength() {
        return Short.toUnsignedInt(len) - Ipv4Header.HEADER_LEN;
    }

    /**
     * Payload + options + header length
     */
    public int totalLength() {
        return Short.toUnsignedInt(len);
    }

    /**
     * Payload length (no header or options)
     */
    public int payloadLength() {
        return totalLength() - Ipv4Header.HEADER_LEN - optionsLength();
    }

    private int optionsLength() {
        return options.stream().mapToInt(IpOption::length).sum();
    }

    @Override
    public int pseudoHeaderLength() {
        return PSEUDO_HEADER_LEN;
    }

    public static Ipv4Header decode(ByteBuffer in) {
        return decode(in, true);
    }

    public static Ipv4Header decode(ByteBuffer in, boolean ensureChecksum) {
        in.mark();
        byte version = in.get();
        byte ihl = (byte) (version & 0x0F);
        version = (byte) (version >>> VERSION_SHIFT);
        if(version != VERSION){
            throw new IllegalArgumentException("Unexpected version for IPv4 header! " + version);
        }
        byte dscp = in.get();
        EcnCodePoint ecn = EcnCodePoint.fromType((byte) (dscp & 0b11));
        dscp = (byte) (dscp >>> DSCP_SHIFT);
        short len = in.getShort();
        short identification = in.getShort();
        short fragmentOffset = in.getShort();
        Ipv4Flags flags = Ipv4Flags.decode((byte) (fragmentOffset >>> FLAGS_SHIFT));
        fragmentOffset = (short) (fragmentOffset & 0x1FFF);
        byte ttl = in.get();
        IpProtocol protocol = IpProtocol.fromType(in.get());
        in.getShort(); // Checksum
        Ipv4Address srcIp = Ipv4Address.decode(in);
        Ipv4Address dstIp = Ipv4Address.decode(in);
        in.reset();
        byte[] headerBytes = new byte[HEADER_LEN];
        in.get(headerBytes);
        if(ensureChecksum) {
            IpUtils.ensureInternetChecksum(headerBytes);
        } else {
            IpUtils.verifyInternetChecksum(headerBytes);
        }
        List<IpOption> options = new ArrayList<>();
        int optionsLength = (ihl - 5) * 4;
        while(optionsLength > 0) {
            IpOption option = IpOption.decode(in);
            options.add(option);
            optionsLength -= option.length();
        }
        if(optionsLength != 0) {
            throw new IllegalArgumentException("Could not decode options for the IPv4 header.");
        }
        return new Ipv4Header(dscp, ecn, len, identification, flags, fragmentOffset, ttl, protocol,
                srcIp, dstIp, options);
    }
}
