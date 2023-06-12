#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include "encryption.h"

#define NONCE_SIZE 15


/************************************BEGIN OF AUXILIARY FUNCTIONS*****************************************************/

void handleErrors(){
    fprintf(stderr, "An error occured.\n");
    exit(1);
}

void printPublicKey(const BIGNUM *publicKey){
    char *hexPublicKey = BN_bn2hex(publicKey);
    printf("%s\n", hexPublicKey);
    OPENSSL_free(hexPublicKey);
}

void printHex(unsigned char *data, size_t size){
    for (size_t i = 0; i < size; ++i)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
} 

char* remove_spaces(char* str) {
    if (str == NULL) {
        return NULL;
    }
    int len = strlen(str);
    char* new_str = malloc(len + 1);
    if (new_str == NULL) {
        return NULL;
    }
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (!isspace(str[i])) {
            new_str[j++] = str[i];
        }
    }
    new_str[j] = '\0';
    return new_str;
}

unsigned char* convertFromHex(const char* hex_str) {
    int hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: invalid hex string length.\n");
        exit(1);
    }

    int data_len = hex_len / 2;
    unsigned char* data = (unsigned char*)malloc(data_len * sizeof(unsigned char));
    if (data == NULL) {
        fprintf(stderr, "Error: could not allocate memory.\n");
        exit(1);
    }

    for (int i = 0; i < data_len; i++) {
        sscanf(hex_str + (i * 2), "%2hhx", &data[i]);
    }

    return data;
}

BIGNUM* concatenateBIGNUMs(const BIGNUM* Yb, const BIGNUM* Ya) {
    int Yb_size = BN_num_bytes(Yb);
    unsigned char* Yb_bytes = (unsigned char*)malloc(Yb_size);
    BN_bn2bin(Yb, Yb_bytes);

    int Ya_size = BN_num_bytes(Ya);
    unsigned char* Ya_bytes = (unsigned char*)malloc(Ya_size);
    BN_bn2bin(Ya, Ya_bytes);

    int concatenated_size = Yb_size + Ya_size;
    unsigned char* concatenated_bytes = (unsigned char*)malloc(concatenated_size);
    memcpy(concatenated_bytes, Yb_bytes, Yb_size);
    memcpy(concatenated_bytes + Yb_size, Ya_bytes, Ya_size);

    BIGNUM* concatenated_num = BN_bin2bn(concatenated_bytes, concatenated_size, NULL);

    free(Yb_bytes);
    free(Ya_bytes);
    free(concatenated_bytes);

    return concatenated_num;
}

/************************************END OF AUXILIARY FUNCTIONS*****************************************************/

        
 
/***********************************BEGIN OF MAIN FUNCTION OF THE SERVER*****************************************************/

int main(int argc, char *argv[]) {

    /*Creation of the TCP connection:*/
    char *ip = "127.0.0.1";
    int port = 5931;

    int sock;
    struct sockaddr_in addr;
    socklen_t addr_size;
    char buffer[1024];
    int n;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket error.");
        exit(1);
    }

    memset(&addr, '\0', sizeof(addr));
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = port;

    connect(sock,  (struct sockaddr*)&addr, sizeof(addr));

    printf("Wellcome, we are creating a secure channel...\n");

    char *username = malloc(2048);

/* **********************************BEGIN OF AUTHENTICATION PROTOCOL**************************************************** */

    /*Agreement between client and bank on Diffie-Hellman's parameters, let's SET p and g:*/
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    if (BN_hex2bn(&p, "8F4BBF5DFFEF55D70C1B0108DEF5D1A9B158D2F3844E2FAD95C1B53EF281FC394D64A3B06068085AD2C1EDA5FD48E29FB1E91BC690C97B15C5B1115EAAFDFF04108D6DA3287189AF425376542003E4645F4020F7FD981265974624BD0F92E14779A16344038437A3A9B090826CDCC22A7FA18F6CFF285D143F7C956F08A509D54AF2DC7D25200562EA3D2BF8C36C6B9E3618537B3281F83B78BEFEEE970C1F62295B83DA453A44DFB4147DBEBC2B9535A0E7FFA58E2006E262FDC48F6F7CFF65FD33DA101DA7CADBCE9F390CBA9DB3CAC2BF2B4549EAD4B457E8D7FEFF6239BD5920F83F567650A85DDEB9CD684E3F474639232A46CFDB2DFBFC1E4D21B068B7") == 0) {
        fprintf(stderr, "Error: could not convert p to BIGNUM.\n");
        BN_free(p);
        BN_free(g);
        handleErrors();
    }
    if (BN_hex2bn(&g, "2") == 0) {
        fprintf(stderr, "Error: could not convert g to BIGNUM.\n");
        BN_free(p);
        BN_free(g);
        handleErrors();
    }

    DH *client_params = DH_new();
    DH_set0_pqg(client_params, p, NULL, g);

    if (DH_generate_key(client_params) != 1){
        fprintf(stderr, "Error: could not generate keys for the client.\n");
        handleErrors();
    }

    /*Computing Yb (user's DH public key for the protocol):*/
    BIGNUM *Yb = BN_new();
    const BIGNUM *b = NULL;
    b = DH_get0_priv_key(client_params);
    BN_mod_exp(Yb, g, b, p, BN_CTX_secure_new());
    size_t Yb_size = BN_num_bytes(Yb);

    /*Sending Yb (client's DH public key for the protocol):*/
    char *Yb_hex = BN_bn2hex(Yb);
    int bytes_sent = send(sock, Yb_hex, Yb_size*2, 0);
    if (bytes_sent == -1 || bytes_sent != Yb_size*2) {
        fprintf(stderr, "Error: could not send Yb.\n");
        free(Yb_hex);
        handleErrors();
    }
    printf("Your DH public key:\n");
    printPublicKey(DH_get0_pub_key(client_params));
    printf("\n");
    
    /*Reception of Ya (bank's DH public key for the protocol):*/
    char Ya_hex[513];
    memset(Ya_hex, 0, sizeof(Ya_hex));

    int bytes_received = recv(sock, Ya_hex, sizeof(Ya_hex) - 1, 0);
    if (bytes_received == -1) {
        fprintf(stderr, "Error: could not receive Ya.\n");
        handleErrors();
    }
    Ya_hex[bytes_received] = '\0';

    printf("Bank's DH public key Ya received (%d bytes)\n", bytes_received);

    BIGNUM *Ya = BN_new();
    if (BN_hex2bn(&Ya, Ya_hex) == 0){
        fprintf(stderr, "Error: could not convert Ya in BIGNUM.\n");
        handleErrors();
    }

    printf("Bank's DH public key:\n");
    printPublicKey(Ya);
    printf("\n");

    
    /*Computing the session key:*/
    BIGNUM *session_key = BN_new();
    BN_mod_exp(session_key, Ya, b, p, BN_CTX_secure_new());
    char *secret_key = BN_bn2hex(session_key);
    BN_free(session_key);

    printf("The connection with the bank is now secured.\n");



    /**********FROM NOW ON COMMUNICATIONS ARE ENCRYPTED:**********/

    /*AUTHENTICATION OF THE SERVER:*/
    /*Computing Yb || Ya:*/
    BIGNUM *Yb_Ya = BN_new();
    Yb_Ya = concatenateBIGNUMs(Yb, Ya);
    size_t Yb_Ya_size = BN_num_bytes(Yb_Ya);

    /*Loading the bank's public key to verify the digital signature:*/
    char public_key_file_path[256];
    printf("Please, enter the path to the file containing the bank's public key: ");
    fgets(public_key_file_path, sizeof(public_key_file_path), stdin);
    public_key_file_path[strcspn(public_key_file_path, "\n")] = '\0';

    FILE* client_public_key_file = fopen(public_key_file_path, "r");
    if (client_public_key_file == NULL){
        fprintf(stderr, "Error: could not open bank's public key file.\n");
        
        handleErrors();
    }

    EVP_PKEY *server_public_key = NULL;
    server_public_key = PEM_read_PUBKEY(client_public_key_file, NULL, NULL, NULL);
    fclose(client_public_key_file);
    if (server_public_key == NULL){
        fprintf(stderr, "Error: could not load the public key.\n");
        
        handleErrors();
    }
    
    /*Reception of the signature:*/
    char *received_signature = malloc(2048);
    char *encrypted_received_signature = malloc(2048);
    unsigned char* decrypted_sig_Yb_Ya = malloc(2048);
    int received_bytes_encrypted_received_signature = recv(sock, encrypted_received_signature, 2048, 0);
    if (received_bytes_encrypted_received_signature > 0) {
        received_signature = gcm_decrypt(encrypted_received_signature, secret_key);
        decrypted_sig_Yb_Ya = convertFromHex(received_signature);
        free(encrypted_received_signature);
    } else {
        fprintf(stderr, "Error: could not receive the digital signature.\n");
        free(received_signature);
        free(encrypted_received_signature);
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }


    /*Verification of the signature:*/
    EC_KEY *server_ec_key_verify = EVP_PKEY_get1_EC_KEY(server_public_key);
    if (server_ec_key_verify == NULL){
        fprintf(stderr, "Error: could not retrieve the public key to verify the signature.\n");
        
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }

    const EC_GROUP *ec_group_verify = EC_KEY_get0_group(server_ec_key_verify);

    ECDSA_SIG *signature_verify = ECDSA_SIG_new();
    if (signature_verify == NULL){
        fprintf(stderr, "Error: could not create the structure for the signature.\n");
        
        EC_KEY_free(server_ec_key_verify);
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }


    unsigned char *Yb_Ya_bytes = (unsigned char *)malloc(Yb_Ya_size);
    if (Yb_Ya_bytes == NULL){
        fprintf(stderr, "Error: could not allocate memory for Yb || Ya.\n");
        
        EC_KEY_free(server_ec_key_verify);
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }
    BN_bn2bin(Yb_Ya, Yb_Ya_bytes);

    unsigned char *sig_Yb_Ya = decrypted_sig_Yb_Ya;
    signature_verify = d2i_ECDSA_SIG(&signature_verify, (const unsigned char **)&sig_Yb_Ya, received_bytes_encrypted_received_signature);
    if (signature_verify == NULL){
        fprintf(stderr, "Error: could not convert signature in format DER.\n");
        free(Yb_Ya_bytes);
        
        EC_KEY_free(server_ec_key_verify);
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }

    int verify_result = ECDSA_do_verify(Yb_Ya_bytes, Yb_Ya_size, signature_verify, server_ec_key_verify);
    if (verify_result != 1){
        fprintf(stderr, "Error: could not verify the digital signature of the server.\n");
        free(Yb_Ya_bytes);
        
        EC_KEY_free(server_ec_key_verify);
        EVP_PKEY_free(server_public_key);
        handleErrors();
    }

    free(received_signature);
    /*Signature is verified successfully:*/
    printf("Bank has been successfully authenticated.\n");

    
    /*AUTHENTICATION OF THE CLIENT:*/
    /*Checking if the username is already registered or not:*/
    printf("Please, enter your username: ");
    fgets(username, 2048, stdin);
    username[strcspn(username, "\n")] = '\0';
    char* encrypted_username = gcm_encrypt(username, secret_key);
    send(sock, encrypted_username, strlen(username) + NONCE_SIZE + sizeof(int), 0);
    free(encrypted_username);
    
    char *username_response = malloc(2048);
    char* encrypted_username_response = malloc(2048);
    int received_bytes_encrypted_username_response = recv(sock, encrypted_username_response, 2048, 0);
    if (received_bytes_encrypted_username_response > 0) {
        username_response = gcm_decrypt(encrypted_username_response, secret_key);
        free(encrypted_username_response);
    }

    
    if(strcmp(username_response, "Right") != 0){
        printf("There is no bank account for this username. Please create an account.\n");
        close(sock);
        printf("You are now disconnected.\n");
        exit(1);
    }


    /*Checking password:*/
    bool password_check = false;
    int count = 4;
    char* password = malloc(2048);
    char* password_response = malloc(2048);
    while (!password_check) {
        printf("Please, enter your password: ");
        fgets(password, 2048, stdin);
        password[strcspn(password, "\n")] = '\0';
        char* encrypted_password = gcm_encrypt(password, secret_key);
        send(sock, encrypted_password, strlen(password) + NONCE_SIZE + sizeof(int), 0);
        free(encrypted_password);

        printf("Checking your password...\n");
        char* encrypted_password_response = malloc(2048);
        int received_bytes_encrypted_password_response = recv(sock, encrypted_password_response, 2048, 0);
        if (received_bytes_encrypted_password_response > 0) {
            password_response = gcm_decrypt(encrypted_password_response, secret_key);
            free(encrypted_password_response);
        }

        if (count == 0) {
            char count[] = "Count";
            send(sock, gcm_encrypt(count, secret_key), strlen(count) + NONCE_SIZE + sizeof(int), 0);
            printf("Soory, you have exceeded the number of trials.\n");
            close(sock);
            printf("You are now disconnected.\n");
            free(password);
            free(password_response);
            exit(1);
        }

        if (strcmp(password_response, "Right") != 0) {
            printf("The password is wrong.\n");
            count = count - 1;
            printf("You still have %d trials.\n", count);
            char conti[] = "Continue";
            send(sock, gcm_encrypt(conti, secret_key), strlen(conti) + NONCE_SIZE + sizeof(int), 0);
        } else {
            password_check = true;
            free(password);
            free(password_response);
            char stop[] = "Stop";
            send(sock, gcm_encrypt(stop, secret_key), strlen(stop) + NONCE_SIZE + sizeof(int), 0);
        }
    }

    printf("Password is correct!\n");
    printf("You are now authenticated for the bank as %s.\n", username);

    /*Free the memory BUT KEEP the secret key:*/
    DH_free(client_params);
    EVP_PKEY_free(server_public_key);
    EC_KEY_free(server_ec_key_verify);
    ECDSA_SIG_free(signature_verify);
    free(Yb_Ya_bytes);
    free(username_response);

/***********************************END OF AUTHENTICATION PROTOCOL*****************************************************/
    

/***********************************BEGIN OF BANKING'S OPERATIONS*****************************************************/

    /*Operations to perform:*/
    bool yes = true;
    while(yes){
        int action;
        printf("What do you want to do? \n");
        printf("\n 1. Check balance.");
        printf("\n 2. Make transfer.");
        printf("\n 3. Check history.");
        printf("\n 4. Exit.");
        printf("\n Your choice (1, 2, 3 or 4):\n");
        scanf("%d", &action);
        
        switch (action) {
            case 1: /*Balance:*/
                char check_balance[] = "check his balance";
                send(sock, gcm_encrypt(check_balance, secret_key), strlen(check_balance) + NONCE_SIZE + sizeof(int), 0);

                char *balance = malloc(2048);
                char *userID = malloc(2048);

                char* encrypted_userID = malloc(2048);
                int received_bytes_encrypted_userID = recv(sock, encrypted_userID, 2048, 0);
                if (received_bytes_encrypted_userID > 0) {
                    userID = gcm_decrypt(encrypted_userID, secret_key);
                    printf("Your account ID is: %s. ", userID);
                    free(encrypted_userID);
                } else {
                    printf("Failed to receive userID data.\n");
                }

                char* encrypted_balance = malloc(2048);
                int received_bytes_encrypted_balance = recv(sock, encrypted_balance, 2048, 0);
                if (received_bytes_encrypted_balance > 0) {
                    balance = gcm_decrypt(encrypted_balance, secret_key);
                    printf("Your current balance is: %s", balance);
                    free(encrypted_balance);
                } else {
                    printf("Failed to receive balance data\n");
                }

                free(balance);
                free(userID);
                break;

            case 2: /*Transfer:*/
                char make_transfer[] = "make a transfer";
                send(sock, gcm_encrypt(make_transfer, secret_key), strlen(make_transfer) + NONCE_SIZE + sizeof(int), 0);

                char *amount = malloc(2048);
                char *beneficiary = malloc(2048);
                char *transfer = malloc(2048);

                printf("Enter the beneficiary's name: ");
                scanf("%s", beneficiary);
                char* encrypted_beneficiary = gcm_encrypt(beneficiary, secret_key);
                send(sock, encrypted_beneficiary, strlen(beneficiary) + NONCE_SIZE + sizeof(int), 0);
                free(encrypted_beneficiary);

                printf("Enter the amount: ");
                scanf("%s", amount);
                char* encrypted_amount = gcm_encrypt(amount, secret_key);
                send(sock, encrypted_amount, strlen(amount) + NONCE_SIZE + sizeof(int), 0);
                free(encrypted_amount);

                char* encrypted_transfer = malloc(2048);
                int received_bytes_encrypted_transfer = recv(sock, encrypted_transfer, 2048, 0);
                if (received_bytes_encrypted_transfer > 0) {
                    transfer = gcm_decrypt(encrypted_transfer, secret_key);
                    printf("The transfert is a: %s", transfer);
                    free(encrypted_transfer);
                } else {
                    printf("Failed to receive transfer data.\n");
                }

                free(amount);
                free(beneficiary);
                free(transfer);
                break;

            case 3: /*History:*/
                char check_history[] = "check his history";
                send(sock, gcm_encrypt(check_history, secret_key), strlen(check_history) + NONCE_SIZE + sizeof(int), 0);
                
                char *history = NULL;
                history = malloc(2048 * sizeof(char));

                char* encrypted_history = malloc(2048);
                int received_bytes_encrypted_history = recv(sock, encrypted_history, 2048, 0);
                if (received_bytes_encrypted_history > 0) {
                    history = gcm_decrypt(encrypted_history, secret_key);
                    printf("Your last transactions: \n%s\n", history);
                    free(encrypted_history);
                } else {
                    printf("Failed to receive history data.\n");
                }

                free(history);
                break;

            case 4: /*Leave*/
                char leave[] = "leave the app";
                send(sock, gcm_encrypt(leave, secret_key), strlen(leave) + NONCE_SIZE + sizeof(int), 0);
                yes = false;
                break;

            default: 
                printf("Sorry, the operation asked is not available.\n");
                break;

        }

        while (getchar() != '\n');
    }

/* **********************************END OF BANKING'S OPERATIONS**************************************************** */


    free(secret_key);
    free(username);
    close(sock);
    printf("You are now disconnected. See you soon!\n");

    return 0;
}

/* **********************************END OF MAIN FUNCTION OF THE SERVER**************************************************** */

