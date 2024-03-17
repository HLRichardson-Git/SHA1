#include <iostream>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

class SHA1 {
private:

    static const unsigned int BLOCK_SIZE = 80;

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xc3d2e1f0;

    uint32_t w[BLOCK_SIZE];

    void fillBlock(std::string in, size_t index);
    std::string digest();
    void reset();
    void applySha1Padding(std::string& in);
    uint32_t leftRotate(uint32_t n, size_t rotateAmount);

public:

    SHA1();
    ~SHA1() {}

    std::string hash(std::string in);

};

std::string convertToHex32(uint32_t value) {
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << value;
    return oss.str();
}

void debugOutput(uint32_t t, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e) {
    std::cout << "t = " << t << " " << convertToHex32(a) << " " << convertToHex32(b) << " "
        << convertToHex32(c) << " " << convertToHex32(d) << " " << convertToHex32(e) << std::endl;
}

SHA1::SHA1() {
    // Constructor implementation, if needed
}

std::string SHA1::hash(std::string in) {
    reset();
    applySha1Padding(in);
    //std::cout << "String after padding: " << convertToHex(in) << std::endl;

    for (size_t i = 0; i < in.length(); i += 64) {
        /*std::cout << "\n\n\nBefore filling block: " << std::endl;
        for (int k = 0; k < 80; k++) {
            std::cout << convertToHex32(w[k]) << std::endl;
        }*/
        fillBlock(in, i);
        /*std::cout << "\n\n\nAfter filling block: " << std::endl;
        for (int k = 0; k < 80; k++) {
            std::cout << convertToHex32(w[k]) << std::endl;
        }*/

        // Initialize hash value for this chunk
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // Debug output before main loop
        //debugOutput(0, a, b, c, d, e);

        for (int j = 0; j < 80; ++j) {
            uint32_t f = 0, k = 0;
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = leftRotate(a, 5) + f + e + k + w[j];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;

            // Debug output inside the main loop
            //debugOutput(j + 1, a, b, c, d, e);
        }

        // Add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    //debugOutput(1000, h0, h1, h2, h3, h4);

    return digest();
}

std::string SHA1::digest() {
    uint8_t hash[20];
    hash[0] = (h0 >> 24) & 0xFF;
    hash[1] = (h0 >> 16) & 0xFF;
    hash[2] = (h0 >> 8) & 0xFF;
    hash[3] = h0 & 0xFF;
    hash[4] = (h1 >> 24) & 0xFF;
    hash[5] = (h1 >> 16) & 0xFF;
    hash[6] = (h1 >> 8) & 0xFF;
    hash[7] = h1 & 0xFF;
    hash[8] = (h2 >> 24) & 0xFF;
    hash[9] = (h2 >> 16) & 0xFF;
    hash[10] = (h2 >> 8) & 0xFF;
    hash[11] = h2 & 0xFF;
    hash[12] = (h3 >> 24) & 0xFF;
    hash[13] = (h3 >> 16) & 0xFF;
    hash[14] = (h3 >> 8) & 0xFF;
    hash[15] = h3 & 0xFF;
    hash[16] = (h4 >> 24) & 0xFF;
    hash[17] = (h4 >> 16) & 0xFF;
    hash[18] = (h4 >> 8) & 0xFF;
    hash[19] = h4 & 0xFF;

    std::ostringstream oss;
    for (int i = 0; i < 20; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

void SHA1::reset() {
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    h4 = 0xc3d2e1f0;
}

void SHA1::fillBlock(std::string in, size_t index) {
    for (int j = 0; j < 16; ++j) {
        w[j] = ((in[index + j * 4 + 3] & 0xff)) |
            ((in[index + j * 4 + 2] & 0xff) << 8) |
            ((in[index + j * 4 + 1] & 0xff) << 16) |
            ((in[index + j * 4 + 0] & 0xff) << 24);
    }
    for (int j = 16; j < 80; ++j) {
        w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
    }
}

void SHA1::applySha1Padding(std::string& in) {
    size_t messageLength = in.length() * 8;

    // Add the '1' bit
    in += (char)0x80;

    // Calculate the number of padding bits needed
    size_t paddingBits = 512 - ((messageLength + 8) % 512);

    // Append '0' bits for padding
    //in.append(paddingBits / 8, '\0');
    while ((in.length() % 64) != 56) {
        in += (char)0x00;
    }

    // Append original message length in bits
    for (int i = 7; i >= 0; --i) {
        in += (char)((messageLength >> (i * 8)) & 0xFF);
    }
}

uint32_t SHA1::leftRotate(uint32_t n, size_t rotateAmount) {
    return (n << rotateAmount) | (n >> (32 - rotateAmount));
}

int main()
{   
    SHA1 SHA1Object;
    std::string test = "abc";
    std::string digest = SHA1Object.hash(test);
    std::string expectedDigest = "a9993e364706816aba3e25717850c26c9cd0d89d";
    std::cout << "Digest = " << digest << std::endl;
    std::cout << "Expected Digest = " << digest << std::endl;
    if (digest == expectedDigest) {
        std::cout << "Digests match!" << std::endl;
    }
    else {
        std::cout << "Digests DONT match!" << std::endl;
    }

    return 0;
}
