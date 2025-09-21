package com.github.hirsivaja.ip.ipv6.extension.mobility;


import java.nio.ByteBuffer;

public interface MobilityMessage {
    void encode(ByteBuffer out);
    MobilityMessageType type();
    int length();

    static MobilityMessage decode(ByteBuffer in, MobilityMessageType type) {
        return switch (type) {
            case BINDING_REFRESH_REQUEST -> BindingRefreshRequest.decode(in);
            case HOME_TEST_INIT -> HomeTestInit.decode(in);
            case CARE_OF_TEST_INIT -> CareOfTestInit.decode(in);
            case HOME_TEST -> HomeTest.decode(in);
            case CARE_OF_TEST -> CareOfTest.decode(in);
            case BINDING_UPDATE -> BindingUpdate.decode(in);
            case BINDING_ACKNOWLEDGEMENT -> BindingAcknowledgement.decode(in);
            case BINDING_ERROR -> BindingError.decode(in);
            default -> throw new IllegalArgumentException("Unexpected value: " + type);
        };
    }
}
