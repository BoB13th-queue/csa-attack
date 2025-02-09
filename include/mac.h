#ifndef MAC_H
#define MAC_H

#include <cstdint>
#include <vector>
#include <string>
#include <cstring>   // memcpy, memset
#include <stdexcept> // invalid_argument
#include <iostream>

using namespace std;

class Mac
{
private:
    uint8_t mac[6];

    void string2array(const string &str, uint8_t *arr)
    {
        if (str.size() != 17)
            throw invalid_argument("Invalid MAC string format: " + str);

        for (int i = 0; i < 6; i++)
        {
            arr[i] = static_cast<uint8_t>(stoi(str.substr(i * 3, 2), nullptr, 16));
        }
    }

    string macArrayToString() const
    {
        char buf[18];
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return string(buf);
    }

public:
    Mac() { memset(mac, 0, 6); }

    Mac(const uint8_t mac_[6]) { memcpy(mac, mac_, 6); }

    Mac(const string &mac_) { string2array(mac_, mac); }

    Mac(const Mac &other) { memcpy(mac, other.mac, 6); }

    void setBroadcastMac() { memset(mac, 0xFF, 6); }

    void setNullMac() { memset(mac, 0x00, 6); }

    void setMac(const uint8_t mac_[6]) { memcpy(mac, mac_, 6); }

    void setMac(const string &mac_) { string2array(mac_, mac); }

    string toString() const { return macArrayToString(); }

    vector<uint8_t> toBytes() const
    {
        return vector<uint8_t>(mac, mac + 6);
    }

    bool operator==(const Mac &rhs) const { return memcmp(mac, rhs.mac, 6) == 0; }
    bool operator!=(const Mac &rhs) const { return !(*this == rhs); }
    bool operator<(const Mac &rhs) const { return memcmp(mac, rhs.mac, 6) < 0; }
    bool operator>(const Mac &rhs) const { return memcmp(mac, rhs.mac, 6) > 0; }
    bool operator<=(const Mac &rhs) const { return memcmp(mac, rhs.mac, 6) <= 0; }
    bool operator>=(const Mac &rhs) const { return memcmp(mac, rhs.mac, 6) >= 0; }

    Mac &operator=(const Mac &rhs)
    {
        if (this != &rhs)
            memcpy(mac, rhs.mac, 6);
        return *this;
    }

    Mac &operator=(const uint8_t mac_[6])
    {
        memcpy(mac, mac_, 6);
        return *this;
    }

    Mac &operator=(const string &mac_)
    {
        string2array(mac_, mac);
        return *this;
    }

    friend ostream &operator<<(ostream &os, const Mac &mac)
    {
        os << mac.toString();
        return os;
    }

    bool isValid() const
    {
        for (int i = 0; i < 6; i++)
            if (mac[i])
                return true;
        return false;
    }
};

#endif // MAC_H
