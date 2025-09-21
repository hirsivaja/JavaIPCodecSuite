package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record PvdIdRouterAdvertisementOption(byte flags, byte delay, short sequenceNumber, DomainName pvdIdFqdn, ByteArray raMessageHeader, List<NdpOption> options) implements NdpOption {

    public PvdIdRouterAdvertisementOption(byte flags, byte delay, short sequenceNumber, DomainName pvdIdFqdn, byte[] raMessageHeader, List<NdpOption> options) {
        this(flags, delay, sequenceNumber, pvdIdFqdn, new ByteArray(raMessageHeader), options);
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.put(flags);
        out.put(delay);
        out.putShort(sequenceNumber);
        pvdIdFqdn.encode(out);
        out.put(new byte[8 - (6 + pvdIdFqdn.length() % 8)]);
        out.put(raMessageHeader.array());
        for(NdpOption option : options) {
            option.encode(out);
        }
    }

    @Override
    public int length() {
        int len = 6 + pvdIdFqdn.length();
        int paddingLen = 8 - (len % 8);
        return len + paddingLen + raMessageHeader.length() + options.stream().mapToInt(NdpOption::length).sum();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.PVD_ID_ROUTER_ADVERTISEMENT;
    }

    public static PvdIdRouterAdvertisementOption decode(ByteBuffer in){
        byte flags = in.get();
        byte delay = in.get();
        short sequenceNumber = in.getShort();
        DomainName pvdIdFqdn = DomainName.decode(in);
        int lenSoFar = 6 + pvdIdFqdn.length();
        byte[] padding = new byte[8 - (lenSoFar % 8)];
        in.get(padding);
        int raMessageHeaderLen = (flags & 0x3F) > 0 ? 16 : 0;
        byte[] raMessageHeader = new byte[raMessageHeaderLen];
        in.get(raMessageHeader);
        List<NdpOption> options = new ArrayList<>();
        while(in.hasRemaining()) {
            NdpOption option = NdpOption.decode(in);
            options.add(option);
        }
        return new PvdIdRouterAdvertisementOption(flags, delay, sequenceNumber, pvdIdFqdn, raMessageHeader, options);
    }
}
