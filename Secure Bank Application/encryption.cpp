#include <iostream> 
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <random>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "encryption.h"


#define NONCE_SIZE 15

using namespace std;
EVP_MD_CTX* shared_ctx = NULL; 


/************************************BEGIN OF AUXILIARY FUNCTIONS*****************************************************/

int handleErrors(){
	printf("An error occourred.\n");
	exit(1);
}

unsigned char* generate_nonce(int size) {
    unsigned char* nonce = new unsigned char[size];

    static int counter = 0;

    for (int i = 0; i < size - sizeof(int); i++) {
        nonce[i] = 0;
    }

    memcpy(nonce + size - sizeof(int), &counter, sizeof(int));
    counter++;
    return nonce;
}

char* concatenateData(const unsigned char* data1, int data1_len, const unsigned char* data2, int data2_len) {
    char* result = new char[data1_len + data2_len];
    memcpy(result, data1, data1_len);
    memcpy(result + data1_len, data2, data2_len);
    return result;
}

std::string read_private_key(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Impossible to read the file " << filename << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

unsigned char* extract_private_key(const std::string& private_key_str) {
    BIO* bio = BIO_new_mem_buf(private_key_str.c_str(), -1);
    if (!bio) {
        std::cerr << "Error: could not create the BIO" << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        std::cerr << "Error: could not read the private key" << std::endl;
        return nullptr;
    }
    unsigned char* private_key = nullptr;
    int private_key_len = i2d_PrivateKey(pkey, &private_key);
    EVP_PKEY_free(pkey);
    if (private_key_len <= 0) {
        std::cerr << "Error: could not retrieve the private key" << std::endl;
        return nullptr;
    }
    return private_key;
}

/************************************END OF AUXILIARY FUNCTIONS*****************************************************/
 

extern "C" {

    char* gcm_encrypt(char* plaintext, unsigned char* secret_key) {
        unsigned char* nonce = generate_nonce(NONCE_SIZE);
        unsigned char* ciphertext = nullptr;
        int ciphertext_len = 0;
        int max_attempts = 150;
        int attempts = 0;

        do {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
            EVP_EncryptInit_ex(ctx, NULL, NULL, secret_key, nonce);

            int plaintext_len = strlen(plaintext);
            ciphertext_len = plaintext_len + EVP_CIPHER_CTX_block_size(ctx);
            ciphertext = new unsigned char[ciphertext_len];
            int update_len = 0;
            int final_len = 0;
            EVP_EncryptUpdate(ctx, NULL, &update_len, nonce, NONCE_SIZE); // nonce here plays the role of the AAD data
            EVP_EncryptUpdate(ctx, ciphertext, &update_len, reinterpret_cast<unsigned char*>(plaintext), plaintext_len);
            EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &final_len);
            ciphertext_len = update_len + final_len;

            EVP_CIPHER_CTX_free(ctx);

            attempts++;
        } while (attempts < max_attempts && ciphertext_len == 0);

        if (ciphertext_len == 0) {
            std::cerr << "Error the cipher failed after many attempts.\n";
            delete[] ciphertext;
            delete[] nonce;
            exit(1);
        }

        int prefixed_ciphertext_len = ciphertext_len + sizeof(int);
        unsigned char* prefixed_ciphertext = new unsigned char[prefixed_ciphertext_len];

        memcpy(prefixed_ciphertext, &ciphertext_len, sizeof(int));

        memcpy(prefixed_ciphertext + sizeof(int), ciphertext, ciphertext_len);

        char* result = concatenateData(nonce, NONCE_SIZE, prefixed_ciphertext, prefixed_ciphertext_len);

        delete[] ciphertext;
        delete[] prefixed_ciphertext;
        delete[] nonce;

        return result;
    }

    char* gcm_decrypt(char* ciphertext, unsigned char* secret_key) {
        unsigned char nonce[NONCE_SIZE];
        memcpy(nonce, ciphertext, NONCE_SIZE);
        unsigned char* prefixed_ciphertext = reinterpret_cast<unsigned char*>(ciphertext + NONCE_SIZE);

        int ciphertext_len = 0;
        memcpy(&ciphertext_len, prefixed_ciphertext, sizeof(int));

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, secret_key, nonce);

        int plaintext_len = ciphertext_len + EVP_CIPHER_CTX_block_size(ctx);
        unsigned char* plaintext = new unsigned char[plaintext_len];
        int update_len = 0;
        int final_len = 0;
        EVP_DecryptUpdate(ctx, NULL, &update_len, nonce, NONCE_SIZE);
        EVP_DecryptUpdate(ctx, plaintext, &update_len, prefixed_ciphertext + sizeof(int), ciphertext_len);
        EVP_DecryptFinal_ex(ctx, plaintext + update_len, &final_len);
        plaintext_len = update_len + final_len;

        char* result = new char[plaintext_len + 1];
        memcpy(result, plaintext, plaintext_len);
        result[plaintext_len] = '\0';

        delete[] plaintext;
        EVP_CIPHER_CTX_free(ctx);

        return result;
    }
    
    char* cbc_encrypt(char* clear_file_name){
        int ret;

        FILE* clear_file = fopen(clear_file_name, "rb");
        if (!clear_file) {
            cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n";
            exit(1);
        }

        fseek(clear_file, 0, SEEK_END);
        long int clear_size = ftell(clear_file);
        fseek(clear_file, 0, SEEK_SET);

        unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
        if (!clear_buf) {
            cerr << "Error: malloc returned NULL (file too big?)\n";
            exit(1);
        }
        ret = fread(clear_buf, 1, clear_size, clear_file);
        if (ret < clear_size) {
            cerr << "Error while reading file '" << clear_file_name << "'\n";
            exit(1);
        }
        fclose(clear_file);

        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        int iv_len = EVP_CIPHER_iv_length(cipher);
        int block_size = EVP_CIPHER_block_size(cipher);

        std::string private_key_str = read_private_key("bank/private_key.txt");
        unsigned char* key = extract_private_key(private_key_str);

        unsigned char* iv = (unsigned char*)malloc(iv_len);
        RAND_poll();
        ret = RAND_bytes((unsigned char*)&iv[0], iv_len);
        if (ret != 1) {
            cerr << "Error: RAND_bytes Failed\n";
            exit(1);
        }

        if (clear_size > INT_MAX - block_size) {
            cerr << "Error: integer overflow (file too big?)\n";
            exit(1);
        }

        int enc_buffer_size = clear_size + block_size;
        unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
        if (!cphr_buf) {
            cerr << "Error: malloc returned NULL (file too big?)\n";
            exit(1);
        }

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
            exit(1);
        }
        ret = EVP_EncryptInit(ctx, cipher, key, iv);
        if (ret != 1) {
            cerr << "Error: EncryptInit Failed\n";
            exit(1);
        }
        int update_len = 0; 
        int total_len = 0;  

        ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
        if (ret != 1) {
            cerr << "Error: EncryptUpdate Failed\n";
            exit(1);
        }
        total_len += update_len;

        ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
        if (ret != 1) {
            cerr << "Error: EncryptFinal Failed\n";
            exit(1);
        }
        total_len += update_len;
        int cphr_size = total_len;

        EVP_CIPHER_CTX_free(ctx);

    #pragma optimize("", off)
        memset(clear_buf, 0, clear_size);
    #pragma optimize("", on)
        free(clear_buf);

        char* cphr_file_name = (char*)malloc(strlen(clear_file_name) + 5);
        strcpy(cphr_file_name, clear_file_name);
        strcat(cphr_file_name, ".enc");
        FILE* cphr_file = fopen(cphr_file_name, "wb");
        if (!cphr_file) {
            cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n";
            exit(1);
        }

        ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
        if (ret < EVP_CIPHER_iv_length(cipher)) {
            cerr << "Error while writing the file '" << cphr_file_name << "'\n";
            exit(1);
        }

        ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
        if (ret < cphr_size) {
            cerr << "Error while writing the file '" << cphr_file_name << "'\n";
            exit(1);
        }

        fclose(cphr_file);

        return cphr_file_name;
    }

    char* cbc_decrypt(char* cphr_file_name){
        int ret;
        std::string private_key_str = read_private_key("bank/private_key.txt");
        unsigned char* key = extract_private_key(private_key_str);

        FILE* cphr_file = fopen(cphr_file_name, "rb");
        if (!cphr_file) {
            cerr << "Error: cannot open file '" << cphr_file_name << "' (file does not exist?)\n";
            exit(1);
        }

        fseek(cphr_file, 0, SEEK_END);
        long int cphr_file_size = ftell(cphr_file);
        fseek(cphr_file, 0, SEEK_SET);

        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        int iv_len = EVP_CIPHER_iv_length(cipher);

        unsigned char* iv = (unsigned char*)malloc(iv_len);
        int cphr_size = cphr_file_size - iv_len;
        unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
        unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
        if (!iv || !cphr_buf || !clear_buf) {
            cerr << "Error: malloc returned NULL (file too big?)\n";
            exit(1);
        }

        ret = fread(iv, 1, iv_len, cphr_file);
        if (ret < iv_len) {
            cerr << "Error while reading file '" << cphr_file_name << "'\n";
            exit(1);
        }
        ret = fread(cphr_buf, 1, cphr_size, cphr_file);
        if (ret < cphr_size) {
            cerr << "Error while reading file '" << cphr_file_name << "'\n";
            exit(1);
        }
        fclose(cphr_file);

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
            exit(1);
        }
        ret = EVP_DecryptInit(ctx, cipher, key, iv);
        if (ret != 1) {
            cerr << "Error: DecryptInit Failed\n";
            exit(1);
        }

        int update_len = 0; 
        int total_len = 0;  

        ret = EVP_DecryptUpdate(ctx, clear_buf, &update_len, cphr_buf, cphr_size);
        if (ret != 1) {
            cerr << "Error: DecryptUpdate Failed\n";
            exit(1);
        }
        total_len += update_len;

        ret = EVP_DecryptFinal(ctx, clear_buf + total_len, &update_len);
        if (ret != 1) {
            cerr << "Error: DecryptFinal Failed\n";
            exit(1);
        }
        total_len += update_len;
        int clear_size = total_len;

        EVP_CIPHER_CTX_free(ctx);

        char* clear_file_name = (char*)malloc(strlen(cphr_file_name) + 5);
        strcpy(clear_file_name, cphr_file_name);
        strcat(clear_file_name, ".dec");

        FILE* clear_file = fopen(clear_file_name, "wb");
        if (!clear_file) {
            cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n";
            exit(1);
        }
        ret = fwrite(clear_buf, 1, clear_size, clear_file);
        if (ret < clear_size) {
            cerr << "Error while writing the file '" << clear_file_name << "'\n";
            exit(1);
        }
        fclose(clear_file);

    #pragma optimize("", off)
        memset(clear_buf, 0, clear_size);
    #pragma optimize("", on)
        free(clear_buf);

        return clear_file_name;
    }

    char* sha256_hash(const char* data, const char* salt){
        unsigned char digest[SHA256_DIGEST_LENGTH];
        char *input = (char*)malloc(2048);
        strcpy(input, data);
        strcat(input, salt);
        SHA256((unsigned char*)input, strlen(input), digest);

        char* hash = new char[2 * SHA256_DIGEST_LENGTH + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            sprintf(hash + (i * 2), "%02x", digest[i]);
        }

        free(input);
        return hash;
    }

}   