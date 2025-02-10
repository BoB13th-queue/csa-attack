#ifndef BEACONFRAME_H
#define BEACONFRAME_H

#include <cstdint>
#include <iostream>

#include "mac.h"
#include "fixedparam.h"
#include "tagedparam.h"

/* 802.11 무선 프레임 헤더 */
// BeaconFrame 클래스 (매니지먼트 프레임의 한 예)
// - MAC 헤더, 고정 파라미터, 태그드 파라미터를 포함합니다.
class BeaconFrame
{
public:
    // MAC 헤더 (총 24바이트)
    uint16_t frameControl;    // 프레임 제어 (2바이트)
    uint16_t duration;        // Duration (2바이트)
    Mac destAddress;          // 목적지 MAC 주소 (6바이트)
    Mac srcAddress;           // 송신자 MAC 주소 (6바이트)
    Mac bssid;                // BSSID (6바이트)
    uint16_t sequenceControl; // 시퀀스 제어 (2바이트)

    // 고정 파라미터 (비콘 프레임의 경우 12바이트)
    ManagementFixedParameters fixedParams;

    // 태그드 파라미터 (Information Elements)
    TaggedParameters taggedParams;

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> bytes;
        // MAC 헤더 직렬화
        bytes.push_back(static_cast<uint8_t>(frameControl & 0xFF));
        bytes.push_back(static_cast<uint8_t>((frameControl >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(duration & 0xFF));
        bytes.push_back(static_cast<uint8_t>((duration >> 8) & 0xFF));
        {
            auto macBytes = destAddress.toBytes();
            bytes.insert(bytes.end(), macBytes.begin(), macBytes.end());
        }
        {
            auto macBytes = srcAddress.toBytes();
            bytes.insert(bytes.end(), macBytes.begin(), macBytes.end());
        }
        {
            auto macBytes = bssid.toBytes();
            bytes.insert(bytes.end(), macBytes.begin(), macBytes.end());
        }
        bytes.push_back(static_cast<uint8_t>(sequenceControl & 0xFF));
        bytes.push_back(static_cast<uint8_t>((sequenceControl >> 8) & 0xFF));

        // 고정 파라미터 직렬화
        auto fixedBytes = fixedParams.toBytes();
        bytes.insert(bytes.end(), fixedBytes.begin(), fixedBytes.end());

        // 태그드 파라미터 직렬화
        auto taggedBytes = taggedParams.toBytes();
        bytes.insert(bytes.end(), taggedBytes.begin(), taggedBytes.end());

        return bytes;
    }

    void parseBytes(const std::vector<uint8_t> &bytes)
    {
        // 최소 길이 검사: MAC 헤더(24바이트) + 고정 파라미터(12바이트) = 36바이트
        if (bytes.size() < 36)
        {
            throw std::runtime_error("비콘 프레임 데이터를 위한 최소 길이(36바이트)가 부족합니다.");
        }
        size_t offset = 0;
        // MAC 헤더 파싱
        frameControl = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;
        duration = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;
        {
            uint8_t tmp[6];
            for (int i = 0; i < 6; i++)
            {
                tmp[i] = bytes[offset++];
            }
            destAddress = tmp;
        }
        {
            uint8_t tmp[6];
            for (int i = 0; i < 6; i++)
            {
                tmp[i] = bytes[offset++];
            }
            srcAddress = tmp;
        }
        {
            uint8_t tmp[6];
            for (int i = 0; i < 6; i++)
            {
                tmp[i] = bytes[offset++];
            }
            bssid = tmp;
        }
        sequenceControl = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;

        // 고정 파라미터 파싱
        fixedParams.parseBytes(bytes, offset);

        // 태그드 파라미터 파싱
        taggedParams.parseBytes(bytes, offset);
    }

    void parseBytes(const uint8_t *bytes, size_t length)
    {
        std::vector<uint8_t> vec(bytes, bytes + length);
        parseBytes(vec);
    }

    friend std::ostream &operator<<(std::ostream &os, const BeaconFrame &frame)
    {
        os << "FrameControl: " << std::hex << frame.frameControl << std::dec << std::endl;
        os << "Duration: " << frame.duration << std::endl;
        os << "DestAddress: " << frame.destAddress << std::endl;
        os << "SrcAddress: " << frame.srcAddress << std::endl;
        os << "BSSID: " << frame.bssid << std::endl;
        os << "SequenceControl: " << std::hex << frame.sequenceControl << std::dec << std::endl;
        os << "Fixed Parameters: " << std::endl
           << frame.fixedParams;
        os << "Tagged Parameters: " << std::endl
           << frame.taggedParams << std::endl;
        return os;
    }
};

#endif // BEACONFRAME_H
