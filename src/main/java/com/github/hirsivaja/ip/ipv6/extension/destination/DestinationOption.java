package com.github.hirsivaja.ip.ipv6.extension.destination;

import java.nio.ByteBuffer;

public interface DestinationOption {
    byte SKIP = 0;
    byte DISCARD = 1;
    byte DISCARD_AND_SEND_ERROR = 2;
    byte DISCARD_AND_SEND_ERROR_IF_NOT_MULTICAST = 3;

    void encode(ByteBuffer out);

    int length();

    DestinationOptionType optionType();

    static DestinationOption decode(ByteBuffer in) {
        DestinationOptionType optionType = DestinationOptionType.fromType(in.get());
        if(optionType == DestinationOptionType.PAD_1) {
            return Pad1.decode();
        }
        int optionLength = Byte.toUnsignedInt(in.get());
        byte[] optionBytes = new byte[optionLength];
        in.get(optionBytes);
        ByteBuffer optionBuffer = ByteBuffer.wrap(optionBytes);
        return switch (optionType) {
            case PAD_N -> PadN.decode(optionBuffer);
            case JUMBO_PAYLOAD -> JumboPayload.decode(optionBuffer);
            case RPL, RPL_DISCARD -> Rpl.decode(optionBuffer);
            case TUNNEL_ENCAPSULATION_LIMIT -> TunnelEncapsulationLimit.decode(optionBuffer);
            case ROUTER_ALERT -> RouterAlert.decode(optionBuffer);
            case QUICK_START -> QuickStart.decode(optionBuffer);
            case CALIPSO -> Calipso.decode(optionBuffer);
            case SMF_DPD -> SmfDpd.decode(optionBuffer);
            case HOME_ADDRESS -> HomeAddress.decode(optionBuffer);
            case ILNP_NONCE -> IlnpNonce.decode(optionBuffer);
            case LINE_IDENTIFICATION -> LineIdentificationOption.decode(optionBuffer);
            case MPL, MPL_DEPRECATED -> Mpl.decode(optionBuffer);
            case IP_DFF -> IpDff.decode(optionBuffer);
            case PDM -> Pdm.decode(optionBuffer);
            case MINIMUM_PATH_MTU -> MinimumPathMtu.decode(optionBuffer);
            case IOAM, IOAM_CHANGEABLE -> Ioam.decode(optionBuffer);
            case ALTMARK -> AltMark.decode(optionBuffer);
            default -> GenericDestinationOption.decode(optionBuffer, optionType);
        };
    }
}
