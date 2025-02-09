#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <csignal>

#include <pcap.h>

#include "mac.h"
#include "radiotap.h"
#include "beaconframe.h"
#include "fixedparam.h"
#include "tagedparam.h"

using namespace std;

static void usage()
{
    cerr << "syntax : csa-attack <interface> <ap mac> [<station mac>]" << endl
         << "sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
}

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 4)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    // 명령줄 인자 파싱
    string iface = argv[1];
    Mac ap_mac = Mac(argv[2]);

    // AP MAC 주소가 유효하지 않으면 에러 메시지를 출력하고 프로그램을 종료한다.
    if (!ap_mac.isValid())
    {
        cerr << "Invalid AP MAC address: " << argv[2] << endl;
        exit(EXIT_FAILURE);
    }

    Mac st_mac = Mac("FF:FF:FF:FF:FF:FF");

    // argc가 4일 때
    if (argc == 4)
    {
        st_mac = Mac(argv[3]);

        // Station MAC 주소가 유효하지 않으면 에러 메시지를 출력하고 프로그램을 종료한다.
        if (!st_mac.isValid())
        {
            cerr << "Invalid Station MAC address: " << argv[3] << endl;
            exit(EXIT_FAILURE);
        }
    }

    // ctrl c 동작 설정
    signal(SIGINT, [](int)
           {
        cout << "Quit" << endl;
        exit(EXIT_SUCCESS); });
    signal(SIGTERM, [](int)
           {
        cout << "Quit" << endl;
        exit(EXIT_SUCCESS); });

    // 설정 값 출력
    cout << "========================================" << endl;
    cout << "Interface: " << iface << endl;
    cout << "AP MAC: " << ap_mac << endl;
    cout << "Station MAC: " << st_mac << endl;
    cout << "========================================" << endl;
    cout << "Press Ctrl-C to quit" << endl;
    cout << "========================================" << endl;

    // pcap 설정
    char errbuf[PCAP_ERRBUF_SIZE];
    // promiscuous=1, read_timeout=1000ms
    pcap_t *handle = pcap_open_live(iface.c_str(), 1024, 1, 1000, errbuf);
    if (!handle)
    {
        cerr << "pcap_open_live(" << iface << ") failed: " << errbuf << endl;
        exit(EXIT_FAILURE);
    }

    // Radiotap/Monitor check
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
    {
        cerr << "[-] Not a Radiotap(802.11) interface. Try enabling monitor mode.\n";
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // 패킷 수신

    while (true)
    {
        // print packet
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        // Radiotap 헤더 파싱
        RadiotapHeader radiotapHeader;
        radiotapHeader.parseBytes(packet, header->caplen);

        // 802.11 프레임 시작 위치 계산
        size_t offset = radiotapHeader.it_len;
        BeaconFrame beaconFrame;
        beaconFrame.parseBytes(packet + offset);

        if (beaconFrame.bssid != ap_mac)
        {
            continue;
        }
        // Radiotap 헤더 출력
        cout << "Radiotap Header" << endl
             << radiotapHeader;
        // Beacon 프레임 출력
        cout << "Beacon Frame" << endl
             << beaconFrame;
        cout << "========================================" << endl;
    }

    pcap_close(handle);
    return 0;
}
