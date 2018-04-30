// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x28;
        pchMessageStart[1] = 0x44;
        pchMessageStart[2] = 0x15;
        pchMessageStart[3] = 0x06;
        vAlertPubKey = ParseHex("");
        // myfix for port
        nDefaultPort = 20582;//11933;
        nRPCPort = 20583;//12934;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        const char* pszTimestamp = "IZEcoin timestamp 170719192518";
        CTransaction txNew;
        txNew.nTime = 1524933676;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1524933676;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        // myfix for nonce
        genesis.nNonce   = 4191303; // 2^22
		
        // myfix
        if (false && genesis.GetHash() != hashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
            uint256 thash;
            //char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
 
            while(1)
            {
#if defined(USE_SSE2)
                // Detection would work, but in cases where we KNOW it always has SSE2,
                // it is faster to use directly than to use a function pointer or conditional.
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || (defined(MAC_OSX) && defined(__i386__))
                // Always SSE2: x86_64 or Intel MacOS X
                Hash9(BEGIN(genesis.nVersion), BEGIN(thash));
#else
                // Detect SSE2: 32bit x86 Linux or Windows
                Hash9(BEGIN(genesis.nVersion), BEGIN(thash));
#endif
#else
                // Generic scrypt
                Hash9(BEGIN(genesis.nVersion), BEGIN(thash));
#endif
                if (thash <= hashTarget)
                    break;
                if ((genesis.nNonce & 0xFFF) == 0)
                {
                    printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        }

		hashGenesisBlock = genesis.GetHash();
        LogPrintStr("\ngenesis hash:");
        LogPrintStr(hashGenesisBlock.ToString().c_str());
        LogPrintStr("\n");
        assert(hashGenesisBlock == uint256("0x021984fd22156ea8d8d86eaa94dc678a5da42a718adb1514d2dddb83b540ce24"));
        //assert(hashGenesisBlock == uint256("0x00000acb9b911eeaca006feec1180ed149b122420b3a2b90c5cf5ab1a0cfdd23"));
        LogPrintStr("\ngenesis.hashMerkleRoot hash:");
        LogPrintStr(genesis.hashMerkleRoot.ToString().c_str());
        LogPrintStr("\n");
        assert(genesis.hashMerkleRoot == uint256("0xefd06609c0755b465e564d67c7a549a2146fef1ce5246c53d8d2da2e4414772c"));
        //assert(genesis.hashMerkleRoot == uint256("0x8ec54a501d49e706f346c8900c2a6ec9e647a68f91557d0b5466705c17d8d21e"));

        vSeeds.push_back(CDNSSeedData("183.182.104.121", "183.182.104.121"));
        vSeeds.push_back(CDNSSeedData("195.201.151.1", "195.201.151.1"));
        vSeeds.push_back(CDNSSeedData("195.201.151.2", "195.201.151.2"));
        vSeeds.push_back(CDNSSeedData("195.201.151.3", "195.201.151.3"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(102);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(132);
        base58Prefixes[SECRET_KEY] =     list_of(171);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xbd;
        pchMessageStart[1] = 0xa5;
        pchMessageStart[2] = 0xd3;
        pchMessageStart[3] = 0xa7;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("");
        nDefaultPort = 21933;
        nRPCPort = 22934;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 172654;
		
        hashGenesisBlock = genesis.GetHash();

        LogPrintStr("\ntest genesis hash:");
        LogPrintStr(hashGenesisBlock.ToString().c_str());
        LogPrintStr("\n");
        assert(hashGenesisBlock == uint256("0x3e2d3359f72c891e59bd2298bad083645b3249396ef8c62d4c8484935e88e2c1"));
        //0x00000acb9b911eeaca006feec1180ed149b122420b3a2b90c5cf5ab1a0cfdd23
        //0x021984fd22156ea8d8d86eaa94dc678a5da42a718adb1514d2dddb83b540ce24

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(80);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
