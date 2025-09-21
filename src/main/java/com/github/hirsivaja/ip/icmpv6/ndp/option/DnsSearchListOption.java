package com.github.hirsivaja.ip.icmpv6.ndp.option;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record DnsSearchListOption(int lifetime, List<DomainName> domainNames) implements NdpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort((short) 0); // RESERVED
        out.putInt(lifetime);
        domainNames.forEach(domainName -> domainName.encode(out));
        int domainNamesLen = domainNames.stream().mapToInt(DomainName::length).sum();
        out.put(new byte[8 - (domainNamesLen % 8)]);
    }

    @Override
    public int length() {
        return 8 + domainNames.stream().mapToInt(DomainName::length).sum();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.DNS_SEARCH_LIST;
    }

    public static DnsSearchListOption decode(ByteBuffer in){
        in.getShort(); // RESERVED
        int lifetime = in.getInt();
        List<DomainName> domainNames = new ArrayList<>();
        int domainNamesLen = 0;
        while(in.hasRemaining() && in.get(in.position()) != 0) {
            DomainName domainName = DomainName.decode(in);
            domainNames.add(domainName);
            domainNamesLen += domainName.length();
        }
        byte[] padding = new byte[8 - (domainNamesLen % 8)];
        in.get(padding);
        return new DnsSearchListOption(lifetime, domainNames);
    }
}
