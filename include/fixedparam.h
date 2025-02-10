#ifndef FIXEDPARAM_H
#define FIXEDPARAM_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <iostream>

// 매니지먼트 프레임 고정 파라미터 (예: Beacon 프레임의 고정 필드)
// - 타임스탬프(8바이트), 비콘 간격(2바이트), Capability 정보(2바이트)
class ManagementFixedParameters
{
public:
    uint64_t timestamp;      // 8바이트
    uint16_t beaconInterval; // 2바이트
    uint16_t capabilityInfo; // 2바이트

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> bytes;
        for (int i = 0; i < 8; i++)
        {
            bytes.push_back(static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF));
        }
        bytes.push_back(static_cast<uint8_t>(beaconInterval & 0xFF));
        bytes.push_back(static_cast<uint8_t>((beaconInterval >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(capabilityInfo & 0xFF));
        bytes.push_back(static_cast<uint8_t>((capabilityInfo >> 8) & 0xFF));
        return bytes;
    }

    // bytes 벡터에서 고정 파라미터를 파싱합니다.
    // offset은 파싱한 만큼 증가시킵니다.
    void parseBytes(const std::vector<uint8_t> &bytes, size_t &offset)
    {
        if (bytes.size() < offset + 12)
        {
            throw std::runtime_error("고정 파라미터를 위한 데이터가 부족합니다.");
        }
        timestamp = 0;
        for (int i = 0; i < 8; i++)
        {
            timestamp |= (static_cast<uint64_t>(bytes[offset++]) << (8 * i));
        }
        beaconInterval = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;
        capabilityInfo = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;
    }

    void parseBytes(const uint8_t *bytes, size_t &offset)
    {
        std::vector<uint8_t> vec(bytes, bytes + 12);
        parseBytes(vec, offset);
    }

    friend std::ostream &operator<<(std::ostream &os, const ManagementFixedParameters &param)
    {
        os << "\ttimestamp: " << std::to_string(param.timestamp) << std::endl
           << "\tbeaconInterval " << std::to_string(param.beaconInterval) << std::endl
           << "\tcapabilityInfo " << std::to_string(param.capabilityInfo) << std::endl;
        return os;
    }
};

#endif // FIXEDPARAM_H