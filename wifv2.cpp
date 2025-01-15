#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <secp256k1.h>

// Function to convert a byte array to a hexadecimal string
std::string to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

// Function to calculate SHA-256 hash
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(EVP_MD_size(EVP_sha256()));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute SHA256 hash");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

// Function to calculate RIPEMD-160 hash
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(EVP_MD_size(EVP_ripemd160()));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute RIPEMD160 hash");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

// Function to convert a private key to a public key using secp256k1
std::vector<unsigned char> private_key_to_public_key(const std::vector<unsigned char>& private_key) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key.data())) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to create public key from private key.");
    }

    // Serialize the public key in compressed format
    std::vector<unsigned char> public_key(33);
    size_t public_key_len = public_key.size();
    secp256k1_ec_pubkey_serialize(ctx, public_key.data(), &public_key_len, &pubkey, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);
    return public_key;
}

// Function to encode data in Base58
std::string base58_encode(const std::vector<unsigned char>& data) {
    static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    BIGNUM* bn = BN_bin2bn(data.data(), data.size(), nullptr);
    if (!bn) throw std::runtime_error("Failed to create BIGNUM");

    std::string base58_address;
    BIGNUM* div = BN_new();
    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!div || !rem || !ctx) {
        BN_free(bn);
        BN_free(div);
        BN_free(rem);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM resources");
    }

    BIGNUM* base = BN_new();
    BN_set_word(base, 58);
    while (!BN_is_zero(bn)) {
        if (!BN_div(div, rem, bn, base, ctx)) {
            BN_free(bn);
            BN_free(div);
            BN_free(rem);
            BN_free(base);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to divide BIGNUM");
        }

        unsigned long rem_word = BN_get_word(rem);
        base58_address = base58_chars[rem_word] + base58_address;
        BN_copy(bn, div);
    }

    // Free resources
    BN_free(bn);
    BN_free(div);
    BN_free(rem);
    BN_free(base);
    BN_CTX_free(ctx);

    // Add leading '1's for each leading zero byte in the input
    for (unsigned char byte : data) {
        if (byte != 0) break;
        base58_address = '1' + base58_address;
    }

    return base58_address;
}

// Function to generate a Bitcoin address from a private key
std::string generate_bitcoin_address(const std::string& private_key_hex) {
    // Convert private key from hex to binary
    std::vector<unsigned char> private_key(private_key_hex.size() / 2);
    for (size_t i = 0; i < private_key.size(); ++i) {
        private_key[i] = std::stoi(private_key_hex.substr(2 * i, 2), nullptr, 16);
    }

    // Step 1: Generate public key from private key
    std::vector<unsigned char> public_key = private_key_to_public_key(private_key);

    // Step 2: Perform SHA-256 hashing on the public key
    std::vector<unsigned char> sha256_hash = sha256(public_key);

    // Step 3: Perform RIPEMD-160 hashing on the SHA-256 hash
    std::vector<unsigned char> ripemd_hash = ripemd160(sha256_hash);

    // Step 4: Add network byte (0x00 for Bitcoin mainnet)
    std::vector<unsigned char> address_data = {0x00};
    address_data.insert(address_data.end(), ripemd_hash.begin(), ripemd_hash.end());

    // Step 5: Perform double SHA-256 hashing for checksum
    std::vector<unsigned char> checksum = sha256(sha256(address_data));
    address_data.insert(address_data.end(), checksum.begin(), checksum.begin() + 4);

    // Step 6: Convert to Base58
    return base58_encode(address_data);
}

int main() {
    std::ifstream infile("private_key.txt");
    std::ofstream outfile("address.txt", std::ios::app);  // Append mode

    if (!infile.is_open() || !outfile.is_open()) {
        std::cerr << "Failed to open input or output file." << std::endl;
        return 1;
    }

    std::string private_key_hex;
    size_t count = 0;
    auto start_time = std::chrono::high_resolution_clock::now();

    // Loop to continuously read private keys and generate addresses
    while (std::getline(infile, private_key_hex)) {
        try {
            // Generate Bitcoin address
            std::string bitcoin_address = generate_bitcoin_address(private_key_hex);

            // Write the address to the output file
            outfile << bitcoin_address << std::endl;
            count++;

            // Print status periodically
            if (count % 100 == 0) {
                auto current_time = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> elapsed = current_time - start_time;
                double speed = count / elapsed.count();
                std::cout << "Addresses generated: " << count << ", Speed: " << speed << " addresses/sec" << std::endl;
            }
        } catch (const std::exception& e) {
            // Skip writing and continue processing other keys
        }
    }

    infile.close();
    outfile.close();

    // Final stats
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_time = end_time - start_time;
    double final_speed = count / total_time.count();
    std::cout << "Total addresses generated: " << count << ", Average speed: " << final_speed << " addresses/sec" << std::endl;

    return 0;
}
