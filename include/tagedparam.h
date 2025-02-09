#ifndef TAGEDPARAM_H
#define TAGEDPARAM_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <algorithm>

// 단일 태그드 파라미터 (Information Element)를 나타내는 클래스
class TaggedParameter
{
public:
    uint8_t id;                // 태그 식별자
    uint8_t length;            // 태그 길이
    std::vector<uint8_t> data; // 태그 데이터

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> bytes;
        bytes.push_back(id);
        bytes.push_back(length);
        if (data.size() != length)
        {
            throw std::runtime_error("태그드 파라미터의 데이터 길이가 length 필드와 일치하지 않습니다.");
        }
        bytes.insert(bytes.end(), data.begin(), data.end());
        return bytes;
    }

    // bytes 벡터에서 단일 태그드 파라미터를 파싱합니다.
    // offset은 파싱한 만큼 증가시킵니다.
    void parseBytes(const std::vector<uint8_t> &bytes, size_t &offset)
    {
        if (offset + 2 > bytes.size())
        {
            throw std::runtime_error("태그드 파라미터 헤더를 위한 데이터가 부족합니다.");
        }
        id = bytes[offset++];
        length = bytes[offset++];
        if (offset + length > bytes.size())
        {
            throw std::runtime_error("태그드 파라미터 데이터를 위한 데이터가 부족합니다.");
        }
        data.assign(bytes.begin() + offset, bytes.begin() + offset + length);
        offset += length;
    }

    void parseBytes(const uint8_t *bytes, size_t &offset)
    {
        std::vector<uint8_t> vec(bytes, bytes + 2);
        parseBytes(vec, offset);
    }

    bool operator==(const TaggedParameter &other) const
    {
        return id == other.id && length == other.length && data == other.data;
    }
    bool operator!=(const TaggedParameter &other) const
    {
        return !(*this == other);
    }
    bool operator<(const TaggedParameter &other) const
    {
        return id < other.id;
    }
    bool operator>(const TaggedParameter &other) const
    {
        return id > other.id;
    }
    bool operator<=(const TaggedParameter &other) const
    {
        return id <= other.id;
    }
    bool operator>=(const TaggedParameter &other) const
    {
        return id >= other.id;
    }

    friend std::ostream &operator<<(std::ostream &os, const TaggedParameter &param)
    {
        os << "TaggedParameter{id=" << std::to_string(param.id) << ", length=" << std::to_string(param.length) << ", data=[";
        for (size_t i = 0; i < param.data.size(); i++)
        {
            os << std::to_string(param.data[i]);
            if (i < param.data.size() - 1)
            {
                os << ", ";
            }
        }
        os << "]}";
        return os;
    }
};

// 여러 태그드 파라미터들을 포함하는 클래스
class TaggedParameters
{
public:
    std::vector<TaggedParameter> parameters;

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> bytes;
        for (const auto &param : parameters)
        {
            auto paramBytes = param.toBytes();
            bytes.insert(bytes.end(), paramBytes.begin(), paramBytes.end());
        }
        return bytes;
    }

    // bytes 벡터에서 태그드 파라미터들을 순차적으로 파싱합니다.
    void parseBytes(const std::vector<uint8_t> &bytes, size_t &offset)
    {
        parameters.clear();
        // 남은 데이터가 최소 2바이트 이상일 때 파싱
        while (offset + 1 < bytes.size())
        {
            TaggedParameter param;
            param.parseBytes(bytes, offset);
            parameters.push_back(param);
        }
    }

    void parseBytes(const uint8_t *bytes, size_t &offset)
    {
        std::vector<uint8_t> vec(bytes, bytes + 2);
        parseBytes(vec, offset);
    }

    void sortById()
    {
        std::sort(parameters.begin(), parameters.end());
    }

    friend std::ostream &operator<<(std::ostream &os, const TaggedParameters &params)
    {
        for (const auto &param : params.parameters)
        {
            os << param << std::endl;
        }
        return os;
    }
};

#endif // TAGEDPARAM_H
