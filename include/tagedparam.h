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

    TaggedParameter() : id(0), length(0), data() {}
    TaggedParameter(uint8_t id, uint8_t length, std::vector<uint8_t> data) : id(id), length(length), data(data) {}

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

    // 벡터 버전: bytes 벡터에서 단일 태그드 파라미터 파싱 (offset이 증가됨)
    void parseBytes(const std::vector<uint8_t> &bytes, size_t &offset)
    {
        id = bytes[offset++];
        length = bytes[offset++];
        if (offset + length > bytes.size())
        {
            throw std::runtime_error("태그드 파라미터 데이터를 위한 데이터가 부족합니다.");
        }
        data.assign(bytes.begin() + offset, bytes.begin() + offset + length);
        offset += length;
    }

    // 포인터 버전: 전체 데이터의 길이(totalLength)를 이용해 파싱
    void parseBytes(const uint8_t *bytes, size_t totalLength, size_t &offset)
    {
        if (offset + 2 > totalLength)
        {
            throw std::runtime_error("--태그드 파라미터 헤더를 위한 데이터가 부족합니다.");
        }
        id = bytes[offset++];
        length = bytes[offset++];
        if (offset + length > totalLength)
        {
            throw std::runtime_error("-태그드 파라미터 데이터를 위한 데이터가 부족합니다.");
        }
        data.assign(bytes + offset, bytes + offset + length);
        offset += length;
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
        os << "id: " << std::to_string(param.id) << std::endl
           << "length: " << std::to_string(param.length) << std::endl
           << "data: {";
        for (size_t i = 0; i < param.data.size(); i++)
        {
            os << std::to_string(param.data[i]);
            if (i < param.data.size() - 1)
            {
                os << ", ";
            }
        }
        os << "}";
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

    // 벡터 버전: bytes 벡터에서 순차적으로 태그드 파라미터들을 파싱
    void parseBytes(const std::vector<uint8_t> &bytes, size_t &offset)
    {
        parameters.clear();
        while (offset + 1 < bytes.size())
        {
            try
            {
                TaggedParameter param;
                param.parseBytes(bytes, offset);
                parameters.push_back(param);
            }
            catch (const std::exception &e)
            {
                break;
            }
        }
    }

    // 포인터 버전: 전체 데이터의 길이(totalLength)를 이용해 순차적으로 파싱
    void parseBytes(const uint8_t *bytes, size_t totalLength, size_t &offset)
    {
        std::vector<uint8_t> vec(bytes, bytes + totalLength);
        parseBytes(vec, offset);
    }

    void sortById()
    {
        std::sort(parameters.begin(), parameters.end());
    }

    friend std::ostream &operator<<(std::ostream &os, const TaggedParameters &params)
    {
        os << "Taged Pram Cnt: " << params.parameters.size() << std::endl;
        for (const auto &param : params.parameters)
        {
            os << param << std::endl;
        }
        return os;
    }
};

#endif // TAGEDPARAM_H
