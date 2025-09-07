package com.github.hirsivaja.ip.igmp;

import java.nio.ByteBuffer;

public interface IgmpMessage {
    int BASE_LEN = 4;

    IgmpType type();
    byte code();
    void encode(ByteBuffer out);
    int length();

    static IgmpMessage decode(ByteBuffer in, IgmpType type, byte code) {
        return switch (type) {
            case CREATE_GROUP_REQUEST,
                CREATE_GROUP_REPLY,
                JOIN_GROUP_REQUEST,
                JOIN_GROUP_REPLY,
                LEAVE_GROUP_REQUEST,
                LEAVE_GROUP_REPLY,
                CONFIRM_GROUP_REQUEST,
                CONFIRM_GROUP_REPLY -> GenericIgmpV0Message.decode(in, type, code);
            case MEMBERSHIP_QUERY -> MembershipQueryMessage.decode(in, type, code);
            case MEMBERSHIP_REPORT_V1 -> GenericIgmpV1Message.decode(in, type, code);
            case MEMBERSHIP_REPORT_V2,
                    LEAVE_GROUP_V2 -> GenericIgmpV2Message.decode(in, type, code);
            case MEMBERSHIP_REPORT_V3 -> MembershipReportV3Message.decode(in, type, code);
            default -> throw new IllegalArgumentException("Unknown IGMP message " + type);
        };
    }
}
