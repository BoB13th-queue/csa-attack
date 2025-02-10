// main.cpp
#include "csaattack.h"

using namespace std;

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 4)
    {
        std::cerr << "Usage: " << argv[0] << " <interface> <ap mac> [<station mac>]" << std::endl;
        return EXIT_FAILURE;
    }
    string iface = argv[1];
    string apmac = argv[2];
    string stationmac = (argc == 4) ? argv[3] : "FF:FF:FF:FF:FF:FF";

    cout << "========================================" << endl;
    cout << "Interface: " << iface << endl;
    cout << "AP MAC: " << apmac << endl;
    cout << "Station MAC: " << stationmac << endl;
    cout << "========================================" << endl;
    cout << "Press Ctrl-C to quit" << endl;
    cout << "========================================" << endl;

    CSAAttack attacker(iface, apmac, stationmac);
    attacker.run();

    return 0;
}
