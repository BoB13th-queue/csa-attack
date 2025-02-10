#ifndef RADIOTAP_HEADER_H
#define RADIOTAP_HEADER_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <iostream>

namespace RadioConstants
{
    constexpr uint8_t RADIO_TAP_VERSION = 0x00;
    constexpr uint32_t FLAG_FLAGS = 0x00000002;
    constexpr uint32_t FLAG_DATA_RATE = 0x00000004;
    constexpr uint32_t FLAG_CHANNEL_FREQ = 0x00000008;
    constexpr uint32_t FLAG_SSI_SIGNAL = 0x00000020;
    constexpr uint32_t FLAG_ANTENNA = 0x00000040;
    constexpr uint32_t FLAG_RX_FLAGS = 0x00000080;
    constexpr uint8_t FCS_FLAG_OFF_MASK = ~0x10;
}

class RadiotapHeader
{
public:
    // Radiotap 고정 필드
    uint8_t it_version; // 버전
    uint8_t it_pad;     // 패딩 (일반적으로 0)
    uint16_t it_len;    // 전체 Radiotap 헤더 길이 (리틀 엔디안)

    // Present 필드: 첫 32비트와 확장된 present 단어들
    uint32_t it_present;                  // 첫 번째 present 워드
    std::vector<uint32_t> it_present_ext; // 확장 present 워드 (있을 경우)

    // Radiotap 가변 필드
    uint8_t flags;          // FLAG_FLAGS가 set된 경우
    uint8_t data_rate;      // FLAG_DATA_RATE가 set된 경우
    uint16_t channel_freq;  // FLAG_CHANNEL_FREQ가 set된 경우: 채널 주파수 (2바이트)
    uint16_t channel_flags; // FLAG_CHANNEL_FREQ가 set된 경우: 채널 플래그 (2바이트, 총 4바이트)
    int8_t ssi_signal;      // FLAG_SSI_SIGNAL가 set된 경우 (음수 표현을 위해 int8_t)
    uint8_t antenna;        // FLAG_ANTENNA가 set된 경우
    uint16_t rx_flags;      // FLAG_RX_FLAGS가 set된 경우

    // Radiotap 헤더를 바이트 벡터로 직렬화
    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> bytes;

        // 고정 필드 직렬화
        bytes.push_back(it_version);
        bytes.push_back(it_pad);
        bytes.push_back(static_cast<uint8_t>(it_len & 0xFF));
        bytes.push_back(static_cast<uint8_t>((it_len >> 8) & 0xFF));

        // present 필드 직렬화를 위해 전체 present 워드를 준비
        std::vector<uint32_t> present_words;
        present_words.push_back(it_present);
        for (auto ext : it_present_ext)
        {
            present_words.push_back(ext);
        }
        // 첫 번째부터 마지막 전까지 확장 bit(0x80000000)를 set
        for (size_t i = 0; i < present_words.size() - 1; i++)
        {
            present_words[i] |= 0x80000000;
        }
        // 마지막 워드는 확장 bit를 클리어
        if (!present_words.empty())
        {
            present_words.back() &= 0x7FFFFFFF;
        }
        // present 워드를 little-endian 순서로 직렬화 (각 워드 4바이트)
        for (auto word : present_words)
        {
            bytes.push_back(static_cast<uint8_t>(word & 0xFF));
            bytes.push_back(static_cast<uint8_t>((word >> 8) & 0xFF));
            bytes.push_back(static_cast<uint8_t>((word >> 16) & 0xFF));
            bytes.push_back(static_cast<uint8_t>((word >> 24) & 0xFF));
        }

        // 가변 필드는 첫 번째 present 워드를 기준으로 체크 (첫 32비트만 사용)
        uint32_t primary_present = present_words[0];

        if (primary_present & RadioConstants::FLAG_FLAGS)
        {
            bytes.push_back(flags);
        }
        if (primary_present & RadioConstants::FLAG_DATA_RATE)
        {
            bytes.push_back(data_rate);
        }
        if (primary_present & RadioConstants::FLAG_CHANNEL_FREQ)
        {
            // 채널 주파수 (2바이트)
            bytes.push_back(static_cast<uint8_t>(channel_freq & 0xFF));
            bytes.push_back(static_cast<uint8_t>((channel_freq >> 8) & 0xFF));
            // 채널 플래그 (2바이트)
            bytes.push_back(static_cast<uint8_t>(channel_flags & 0xFF));
            bytes.push_back(static_cast<uint8_t>((channel_flags >> 8) & 0xFF));
        }
        if (primary_present & RadioConstants::FLAG_SSI_SIGNAL)
        {
            bytes.push_back(static_cast<uint8_t>(ssi_signal));
        }
        if (primary_present & RadioConstants::FLAG_ANTENNA)
        {
            bytes.push_back(antenna);
        }
        if (primary_present & RadioConstants::FLAG_RX_FLAGS)
        {
            bytes.push_back(static_cast<uint8_t>(rx_flags & 0xFF));
            bytes.push_back(static_cast<uint8_t>((rx_flags >> 8) & 0xFF));
        }

        return bytes;
    }

    // 바이트 벡터를 사용하여 Radiotap 헤더를 파싱
    void parseBytes(const std::vector<uint8_t> &bytes)
    {
        if (bytes.size() < 8)
        {
            throw std::runtime_error("Radiotap 고정 헤더를 위한 데이터가 부족합니다.");
        }
        size_t offset = 0;
        it_version = bytes[offset++];
        it_pad = bytes[offset++];
        it_len = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
        offset += 2;

        // 최소 4바이트의 present 필드 존재 여부 확인
        if (bytes.size() < offset + 4)
        {
            throw std::runtime_error("Radiotap present 필드를 위한 데이터가 부족합니다.");
        }
        it_present = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
        offset += 4;

        // 확장 present 필드 파싱: 최상위 비트가 set된 동안 추가 32비트 워드를 읽음
        it_present_ext.clear();
        while (it_present & 0x80000000)
        {
            if (bytes.size() < offset + 4)
            {
                throw std::runtime_error("확장 Radiotap present 필드를 위한 데이터가 부족합니다.");
            }
            uint32_t ext_word = bytes[offset] | (bytes[offset + 1] << 8) |
                                (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
            offset += 4;
            it_present_ext.push_back(ext_word);
            // 새로 읽은 워드의 확장 비트가 클리어되면 종료
            if ((ext_word & 0x80000000) == 0)
            {
                break;
            }
        }

        // 첫 번째 present 워드를 기준으로 가변 필드 파싱
        uint32_t primary_present = it_present;
        if (primary_present & RadioConstants::FLAG_FLAGS)
        {
            if (offset >= bytes.size())
                throw std::runtime_error("flags 필드를 위한 데이터가 부족합니다.");
            flags = bytes[offset++];
            flags &= RadioConstants::FCS_FLAG_OFF_MASK; // FCS flag 제거
        }
        if (primary_present & RadioConstants::FLAG_DATA_RATE)
        {
            if (offset >= bytes.size())
                throw std::runtime_error("data_rate 필드를 위한 데이터가 부족합니다.");
            data_rate = bytes[offset++];
        }
        if (primary_present & RadioConstants::FLAG_CHANNEL_FREQ)
        {
            if (offset + 3 >= bytes.size())
                throw std::runtime_error("채널 주파수 및 플래그 필드를 위한 데이터가 부족합니다.");
            channel_freq = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
            offset += 2;
            channel_flags = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
            offset += 2;
        }
        if (primary_present & RadioConstants::FLAG_SSI_SIGNAL)
        {
            if (offset >= bytes.size())
                throw std::runtime_error("ssi_signal 필드를 위한 데이터가 부족합니다.");
            ssi_signal = static_cast<int8_t>(bytes[offset++]);
        }
        if (primary_present & RadioConstants::FLAG_ANTENNA)
        {
            if (offset >= bytes.size())
                throw std::runtime_error("antenna 필드를 위한 데이터가 부족합니다.");
            antenna = bytes[offset++];
        }
        if (primary_present & RadioConstants::FLAG_RX_FLAGS)
        {
            if (offset + 1 >= bytes.size())
                throw std::runtime_error("rx_flags 필드를 위한 데이터가 부족합니다.");
            rx_flags = static_cast<uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
            offset += 2;
        }
    }

    // 원시 바이트 배열로부터 헤더 파싱
    void parseBytes(const uint8_t *bytes, size_t length)
    {
        std::vector<uint8_t> vec(bytes, bytes + length);
        parseBytes(vec);
    }

    friend std::ostream &operator<<(std::ostream &os, const RadiotapHeader &header)
    {
        os << "it_version: " << std::to_string(header.it_version) << std::endl;
        os << "it_pad: " << std::to_string(header.it_pad) << std::endl;
        os << "it_len: " << std::to_string(header.it_len) << std::endl;
        os << "it_present: 0x" << std::hex << header.it_present << std::dec << std::endl;
        for (size_t i = 0; i < header.it_present_ext.size(); i++)
        {
            os << "it_present_ext[" << i << "]: " << std::to_string(header.it_present_ext[i]) << std::endl;
        }
        os << "flags: 0x" << std::hex << std::to_string(header.flags) << std::dec << std::endl;
        os << "data_rate: " << std::to_string(header.data_rate) << std::endl;
        os << "channel_freq: " << std::to_string(header.channel_freq) << std::endl;
        os << "channel_flags: 0x" << std::hex << header.channel_flags << std::dec << std::endl;
        os << "ssi_signal: " << std::to_string(header.ssi_signal) << std::endl;
        os << "antenna: " << std::to_string(header.antenna) << std::endl;
        os << "rx_flags: 0x" << std::hex << header.rx_flags << std::dec << std::endl
           << std::endl;
        return os;
    }
};

#endif // RADIOTAP_HEADER_H
