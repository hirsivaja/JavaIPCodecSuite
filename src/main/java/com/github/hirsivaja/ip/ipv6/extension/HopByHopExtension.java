package com.github.hirsivaja.ip.ipv6.extension;

import com.github.hirsivaja.ip.IpProtocol;
import com.github.hirsivaja.ip.ipv6.extension.destination.DestinationOption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record HopByHopExtension(IpProtocol nextHeader, List<DestinationOption> options) implements ExtensionHeader {

    @Override
    public void encode(ByteBuffer out) {
        out.put(nextHeader.type());
        out.put((byte) (length() / 8 - 1));
        options.forEach(option -> option.encode(out));
    }

    @Override
    public int length() {
        return 2 + options.stream().mapToInt(DestinationOption::length).sum();
    }

    public static ExtensionHeader decode(ByteBuffer in) {
        IpProtocol nextHeader = IpProtocol.fromType(in.get());
        int extensionLen = Byte.toUnsignedInt(in.get()) * 8 + 8;
        int currentLen = 2;
        List<DestinationOption> options = new ArrayList<>();
        while(currentLen < extensionLen) {
            DestinationOption option = DestinationOption.decode(in);
            options.add(option);
            currentLen += option.length();
        }
        return new HopByHopExtension(nextHeader, options);
    }
}
