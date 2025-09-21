package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import com.github.hirsivaja.ip.ipv6.Ipv6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record EncryptedDnsOption(
        short servicePriority,
        int lifetime,
        ByteArray authenticationDomainName,
        List<Ipv6Address> ipv6Addresses,
        ByteArray serviceParams) implements NdpOption {

    public EncryptedDnsOption(short servicePriority, int lifetime, byte[] authenticationDomainName, List<Ipv6Address> ipv6Addresses, byte[] serviceParams) {
        this(servicePriority, lifetime, new ByteArray(authenticationDomainName), ipv6Addresses, new ByteArray(serviceParams));
    }

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length() / 8));
        out.putShort(servicePriority);
        out.putInt(lifetime);
        out.putShort((short) authenticationDomainName.length());
        out.put(authenticationDomainName.array());
        out.putShort((short) (Ipv6Address.IPV6_ADDRESS_LEN * ipv6Addresses.size()));
        ipv6Addresses.forEach(ipv6Address -> ipv6Address.encode(out));
        out.putShort((short) serviceParams.length());
        out.put(serviceParams.array());
        
    }

    @Override
    public int length() {
        return 14 + authenticationDomainName.length() + serviceParams.length() + Ipv6Address.IPV6_ADDRESS_LEN * ipv6Addresses.size();
    }

    @Override
    public NdpOptionType optionType() {
        return NdpOptionType.ENCRYPTED_DNS;
    }

    public static EncryptedDnsOption decode(ByteBuffer in){
        short servicePriority = in.getShort();
        int lifetime = in.getInt();
        int adnLen = Short.toUnsignedInt(in.getShort());
        byte[] authenticationDomainName = new byte[adnLen];
        in.get(authenticationDomainName);
        int addressLen = Short.toUnsignedInt(in.getShort());
        int numberOfAddresses = addressLen / 16;
        List<Ipv6Address> ipv6Addresses = new ArrayList<>();
        for(int i = 0; i < numberOfAddresses; i++) {
            ipv6Addresses.add(Ipv6Address.decode(in));
        }
        int serviceParamsLen = Short.toUnsignedInt(in.getShort());
        byte[] serviceParams = new byte[serviceParamsLen];
        in.get(serviceParams);
        return new EncryptedDnsOption(servicePriority, lifetime, authenticationDomainName, ipv6Addresses, serviceParams);
    }
}
