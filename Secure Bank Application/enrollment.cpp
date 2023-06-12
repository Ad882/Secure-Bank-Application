#include <openssl/ec.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>

/************************************BEGIN OF AUXILIARY FUNCTIONS*****************************************************/

bool generateECCKeyPair(const std::string& publicKeyFile, const std::string& privateKeyFile) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);

    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    FILE* publicKeyFp = fopen(publicKeyFile.c_str(), "w");
    if (publicKeyFp == nullptr || PEM_write_PUBKEY(publicKeyFp, pkey) == 0) {
        fclose(publicKeyFp);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    fclose(publicKeyFp);

    FILE* privateKeyFp = fopen(privateKeyFile.c_str(), "w");
    if (privateKeyFp == nullptr || PEM_write_PKCS8PrivateKey(privateKeyFp, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
        fclose(privateKeyFp);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    fclose(privateKeyFp);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return true;
}

void writeKeyToFile(const std::string& filename, const std::string& key) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << key;
        file.close();
    } else {
        std::cout << "Error: could not read the file: " << filename << std::endl;
    }
}

bool generateUserECCKeyPair(const std::string& username) {
    std::string publicKeyFile = "users/" + username + "/public_key.txt";
    std::string privateKeyFile = "users/" + username + "/private_key.txt";
    std::string publicKeyCopyFile = "clients/passwords/keys/" + username + ".txt";

    std::string directory = "users/" + username;
    struct stat st;
    if (stat(directory.c_str(), &st) != 0) {
        if (mkdir(directory.c_str(), 0777) != 0) {
            std::cerr << "Error: could not create the directory: " << directory << std::endl;
            return false;
        }
    }

    if (generateECCKeyPair(publicKeyFile, privateKeyFile)) {
        std::cout << "The pair of keys has been generated correctly." << std::endl;

        std::ifstream publicKeyFp(publicKeyFile);
        if (publicKeyFp.is_open()) {
            std::string publicKey((std::istreambuf_iterator<char>(publicKeyFp)), std::istreambuf_iterator<char>());
            publicKeyFp.close();

            writeKeyToFile(publicKeyCopyFile, publicKey);

            return true;
        }
    }

    return false;
}

void copyFileToUserDirectory(const std::string& username) {
    const std::string sourceFile = "bank/public_key.txt";

    const std::string destinationDirectory = "users/" + username;

    const std::string destinationFile = destinationDirectory + "/public_key_bank.txt";

    struct stat st;
    if (stat(destinationDirectory.c_str(), &st) != 0) {
        std::cerr << "The final directory does not exist: " << destinationDirectory << std::endl;
        return;
    }

    std::ifstream source(sourceFile, std::ios::binary);
    if (!source) {
        std::cerr << "Impossible to open the source file: " << sourceFile << std::endl;
        return;
    }

    std::ofstream destination(destinationFile, std::ios::binary);
    if (!destination) {
        std::cerr << "Impossible to create the final file: " << destinationFile << std::endl;
        source.close();
        return;
    }

    char ch;
    while (source.get(ch)) {
        destination.put(ch);
    }

    std::cout << "File has been copied with success towards " << destinationFile << std::endl;

    source.close();
    destination.close();
}

/************************************END OF AUXILIARY FUNCTIONS*****************************************************/
  
  
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Please specify a username." << std::endl;
        return 1;
    }

    std::string username = argv[1];
    if (generateUserECCKeyPair(username)) {
        std::cout << "The keys generation for '" << username << "' has been successfully done." << std::endl;
        copyFileToUserDirectory(username);
        return 0;
    } else {
        std::cerr << "Error: could not generate the keys for '" << username << "'." << std::endl;
        return 1;
    }
}
