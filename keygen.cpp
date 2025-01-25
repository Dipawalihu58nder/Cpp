#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <random>
#include <iomanip>

using namespace std;

// Function to generate a random private key
string generatePrivateKey() {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<uint64_t> dis;
    string key;
    for (int i = 0; i < 4; ++i) {
        uint64_t part = dis(gen);
        key += to_string(part);
    }
    return key.substr(0, 64); // Ensure the key is 64 characters long
}

// Function to convert private key to WIF
string privateKeyToWIF(const string &privateKey) {
    string extendedKey = "80" + privateKey; // Add version byte (0x80 for mainnet)
    unsigned char hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)extendedKey.c_str(), extendedKey.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    extendedKey += string((char *)hash2, 4); // Append first 4 bytes of double SHA256 as checksum
    // Encode to base58 (skipped here for brevity)
    return extendedKey; // Placeholder
}

// Function to generate a Bitcoin address from a public key
string publicKeyToAddress(const unsigned char *publicKey, size_t length) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[RIPEMD160_DIGEST_LENGTH];
    SHA256(publicKey, length, hash1);
    RIPEMD160(hash1, SHA256_DIGEST_LENGTH, hash2);
    string address = ""; // Add base58 encoding here (skipped for brevity)
    return address;
}

// Function to load Bitcoin addresses from file
unordered_set<string> loadAddresses(const string &fileName) {
    unordered_set<string> addressSet;
    ifstream file(fileName);
    string line;
    while (getline(file, line)) {
        addressSet.insert(line);
    }
    return addressSet;
}

int main() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unordered_set<string> btcAddresses = loadAddresses("btc.txt");
    ofstream foundFile("found.txt");
    int generatedKeys = 0, foundKeys = 0;

    while (true) {
        string privateKey = generatePrivateKey();
        string wif = privateKeyToWIF(privateKey);

        unsigned char publicKey[65];
        size_t publicKeyLength = 65;
        secp256k1_pubkey pubkey;

        if (secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char *)privateKey.c_str())) {
            secp256k1_ec_pubkey_serialize(ctx, publicKey, &publicKeyLength, &pubkey, SECP256K1_EC_UNCOMPRESSED);
            string address = publicKeyToAddress(publicKey, publicKeyLength);

            if (btcAddresses.find(address) != btcAddresses.end()) {
                foundFile << "Address: " << address << " WIF: " << wif << endl;
                foundKeys++;
            }
        }
        generatedKeys++;

        cout << "\rGenerated: " << generatedKeys << " | Found: " << foundKeys << flush;
    }

    secp256k1_context_destroy(ctx);
    return 0;
}