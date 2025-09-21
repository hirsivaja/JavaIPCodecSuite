package com.github.hirsivaja.ip.icmpv6.ndp.option;

import com.github.hirsivaja.ip.ByteArray;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public record DomainName(List<ByteArray> labels) {

    public void encode(ByteBuffer out) {
        for(int i = 0; i < labels.size(); i++) {
            out.put((byte) labels.get(i).length());
            out.put(labels.get(i).array());
        }
        out.put((byte) 0);
    }

    public int length() {
        return 1 + labels.size() + labels.stream().mapToInt(ByteArray::length).sum();
    }

    public static DomainName decode(ByteBuffer in) {
        List<ByteArray> labels = new ArrayList<>();
        int len = 0;
        do {
            len = Byte.toUnsignedInt(in.get());
            if(len > 0) {
                byte[] label = new byte[len];
                in.get(label);
                labels.add(new ByteArray(label));
            }
        } while (len > 0);
        return new DomainName(labels);
    }
}
