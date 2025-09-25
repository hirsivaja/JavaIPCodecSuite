package com.github.hirsivaja.ip.ipv4.option;

import com.github.hirsivaja.ip.ipv4.Ipv4Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record RecordRoute(byte pointer, List<Ipv4Address> routeData) implements IpOption {

    @Override
    public void encode(ByteBuffer out) {
        out.put(optionType().type());
        out.put((byte) (length()));
        out.put(pointer);
        routeData.forEach(route -> route.encode(out));
    }

    @Override
    public int length() {
        return 3 + routeData.size() * 4;
    }

    @Override
    public IpOptionType optionType() {
        return IpOptionType.RECORD_ROUTE;
    }

    public static RecordRoute decode(ByteBuffer in){
        byte pointer = in.get();
        List<Ipv4Address> routeData = new ArrayList<>();
        while(in.hasRemaining()) {
            routeData.add(Ipv4Address.decode(in));
        }
        return new RecordRoute(pointer, routeData);
    }
}
