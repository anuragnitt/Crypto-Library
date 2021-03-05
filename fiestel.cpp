#include <iostream>
#include <vector>
#include <string>
#include <map>
using namespace std;

vector<uint8_t> string_to_bytes(string& str) {
    vector<uint8_t> bytes;
    for (char ch : str)
        bytes.push_back((uint8_t)ch);
    return bytes;
}

string bytes_to_string(vector<uint8_t>& bytes) {
    string str("");
    for (uint8_t byte : bytes)
        str += (char)byte;
    return str;
}

string int_to_binary(uint8_t num, size_t bits) {
    string binary("");
    for (size_t i=0; i<bits; i++) {
        if (num & 0x80)
            binary += "1";
        else
            binary += "0";
        num <<= 1;
    }
    return binary;
}

uint8_t binary_to_int(string binary) {
    uint8_t num = 0, base = 1;
    for (size_t i=binary.length()-1; i>=0; i--) {
        num += (binary.at(i) - 48)*base;
        base <<= 1;
    }
    return num;
}

vector<uint8_t> binary_to_bytes(string& binary) {
    vector<uint8_t> bytes;
    string byte;
    for (size_t i=0; i<binary.length()/8; i++) {
        byte = binary.substr(i*8, 8);
        bytes.push_back(binary_to_int(byte));
    }
    return bytes;
}

string bytes_to_binary(vector<uint8_t>& bytes) {
    string binary("");
    for (uint8_t byte : bytes)
        binary += int_to_binary(byte, 8);
    return binary;
}

void pad(vector<uint8_t>& plaintext) {
    size_t num = 8 - plaintext.size()%8;
    for (size_t i=0; i<num; i++)
        plaintext.push_back(num);
}

void unpad(vector<uint8_t>& plaintext) {
    size_t index = plaintext.size()-plaintext.back()-1;
    plaintext.erase(plaintext.begin()+index, plaintext.end());
}

void Xor(vector<uint8_t>& bytes_1, vector<uint8_t> bytes_2) {
    if (bytes_1.size() == bytes_2.size()) {
        for (size_t i=0; i<bytes_1.size(); i++)
            bytes_1.at(i) = bytes_1.at(i) ^ bytes_2.at(i);
    }
}

string expand_permutation(vector<uint8_t>& data) {
    vector<uint8_t> table {31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
	                    7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
	                    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
	                    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0};

    vector<string> binary(4);
    for (uint8_t byte : data)
        binary.push_back(int_to_binary(byte, 8));

    string expanded("");
    for (size_t i=0; i<table.size(); i++) {
        uint8_t index = table.at(i);
        expanded += binary.at(index/8).at(index/4);
    }

    return expanded;
}

void s_box(string& data) {
    map<string, vector<vector<string>>> table;
    vector<vector<string>> v1 {{"0000", "0010"}, {"0001", "1100"}, {"0010", "0100"}, {"0011", "0001"}, {"0100", "0111"}, {"0101", "1010"}, {"0110", "1011"}, {"0111", "0110"}, {"1000", "1000"}, {"1001", "0101"}, {"1010", "0011"}, {"1011", "1111"}, {"1100", "1101"}, {"1101", "0000"}, {"1110", "1110"}, {"1111", "1001"}};
    vector<vector<string>> v2 {{"0000", "1110"}, {"0001", "1011"}, {"0010", "0010"}, {"0011", "1100"}, {"0100", "0100"}, {"0101", "0111"}, {"0110", "1101"}, {"0111", "0001"}, {"1000", "0101"}, {"1001", "0000"}, {"1010", "1111"}, {"1011", "1010"}, {"1100", "0011"}, {"1101", "1001"}, {"1110", "1000"}, {"1111", "0110"}};
    vector<vector<string>> v3 {{"0000", "0100"}, {"0001", "0010"}, {"0010", "0001"}, {"0011", "1011"}, {"0100", "1010"}, {"0101", "1101"}, {"0110", "0111"}, {"0111", "1000"}, {"1000", "1111"}, {"1001", "1001"}, {"1010", "1100"}, {"1011", "0101"}, {"1100", "0110"}, {"1101", "0011"}, {"1110", "0000"}, {"1111", "1110"}};
    vector<vector<string>> v4 {{"0000", "1011"}, {"0001", "1000"}, {"0010", "1100"}, {"0011", "0111"}, {"0100", "0001"}, {"0101", "1110"}, {"0110", "0010"}, {"0111", "1101"}, {"1000", "0110"}, {"1001", "1111"}, {"1010", "0000"}, {"1011", "1001"}, {"1100", "1010"}, {"1101", "0100"}, {"1110", "0101"}, {"1111", "0011"}};
    table["00"] = v1;
    table["01"] = v2;
    table["10"] = v3;
    table["11"] = v4;

    string compressed("");
    string x, y, z;
    for (size_t i=0; i<8; i++) {
        x = data.substr(i*6, 6);
        y = x.front() + x.back();
        z = x.substr(1, 4);
        for (vector<string> vect : table[y]) {
            if (vect.at(0) == z) {
                compressed += vect.at(1);
                break;
            }
        }
    }

    data.clear();
    data = compressed;
}

vector<uint8_t> straight_permutation(string& data) {
    vector<uint8_t> table {15, 6, 19, 20, 28, 11, 27, 16,
	                    0, 14, 22, 25, 4, 17, 30, 9,
	                    1, 7, 23, 13, 31, 26, 2, 8,
	                    18, 12, 29, 5, 21, 10, 3, 24};

    vector<uint8_t> bytes;
    string binary("");

    for (size_t i=0; i<table.size(); i++) {
        uint8_t index = table.at(i);
        if ((index + 1)%8 == 0) {
            bytes.push_back(binary_to_int(binary));
            binary.clear();
        }
        binary += data.at(index);
    }

    return bytes;
}

vector<uint8_t> fiestel(vector<uint8_t>& right, vector<uint8_t>& key) {
    string expanded = expand_permutation(right);
    vector<uint8_t> expanded_bytes = binary_to_bytes(expanded);
    Xor(expanded_bytes, key);
    string expanded_binary = bytes_to_binary(expanded_bytes);
    s_box(expanded_binary);
    return straight_permutation(expanded_binary);
}

vector<uint8_t> encrypt(string& pt, vector<uint8_t>& key) {
    vector<uint8_t> plaintext = string_to_bytes(pt);
    pad(plaintext);
    vector<uint8_t> ciphertext, block(8), left(4), right(4);
    for (size_t i=0; i<plaintext.size()/8; i++) {
        copy(plaintext.begin()+i*8, plaintext.begin()+i*8+8+1, block.begin());
        copy(block.begin(), block.begin()+4, left.begin());
        copy(block.begin()+4, block.end(), right.begin());
        Xor(left, fiestel(right, key));
        ciphertext.insert(ciphertext.end(), right.begin(), right.end());
        ciphertext.insert(ciphertext.end(), left.begin(), left.end());
        block.clear();
        left.clear();
        right.clear();
    }
    return ciphertext;
}

int main() {
    string plaintext("anurag goyal");
    vector<uint8_t> key {114, 127, 248, 2, 61, 96};
    vector<uint8_t> cipher = encrypt(plaintext, key);
    return 0;
}
