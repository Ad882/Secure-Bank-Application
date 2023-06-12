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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include "encryption.h"

#define ACCOUNTS_DIR "clients/accounts"
#define NONCE_SIZE 15


/************************************BEGIN OF AUXILIARY FUNCTIONS*****************************************************/

char* get_salt(char* username) {
    char path[256];
    char line[1024];
    char* token;
    char* salt = NULL;

    FILE *fp = fopen("clients/passwords/salts.txt","r"); 

    if (fp == NULL) {
        perror("Error: could not open the file");
    }

    while (fgets(line, 1024, fp) != NULL) {
        token = strtok(line, " -- ");
        if (token == NULL) {
            break;
        } else if (username != NULL && strcmp(token, username) == 0) {
            token = strtok(NULL, " -- ");
            if (token != NULL) {
                salt = token;
                break;
            }
        }
    }

    fclose(fp);

    return salt;
}

bool check_password(char* username, char* password) {
    const char* filename = "clients/passwords/passwords.txt";

    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Impossible to open the file %s.\n", filename);
        return false; 
    }

    char *tag = malloc(2048);
    char line[100];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';

        tag = sha256_hash(password, get_salt(username));
        if (strcmp(tag, line) == 0) {
            fclose(file);
            free(tag);
            return true; 
        }
    }
    free(tag);
    fclose(file);
    return false;
}

char *remove_spaces(char *str) {
    if (str == NULL) {
        return NULL;
    }
    char *new_str = malloc(strlen(str) + 1);
    if (new_str == NULL) {
        return NULL;
    }
    int j = 0;
    for (int i = 0; str[i]; i++) {
        if (!isspace(str[i])) {
            new_str[j++] = str[i];
        }
    }
    new_str[j] = '\0';
    return new_str;
}

bool contains_double(char* amount) {
    char* end;
    strtod(amount, &end);

    if (end == amount || *end != '\0') {
        return false;
    }

    if (amount[0] == '-') {
        return false;
    }

    for (size_t i = 0; i < strlen(amount); i++) {
        if (!isdigit(amount[i]) && amount[i] != '.') {
            return false;
        }
    }

    return true;
}

char* get_ID(char* username) {
    char path[256];
    char line[1024];
    char* token;
    char* ID = NULL;

    FILE *fp = fopen("clients/passwords/userID.txt","r"); 

    if (fp == NULL) {
        perror("Error: could not open the file");
    }

    while (fgets(line, 1024, fp) != NULL) {
        token = strtok(line, " -- ");
        if (token == NULL) {
            break;
        } else if (username != NULL && strcmp(token, username) == 0) {
            token = strtok(NULL, " -- ");
            if (token != NULL) {
                ID = token;
                break;
            }
        }
    }

    fclose(fp);

    return ID;
}

char* get_balance(char* filename) {
    DIR* dir;
    struct dirent* ent;
    char* balance = NULL;

    dir = opendir(ACCOUNTS_DIR);
    if (dir == NULL) {
        perror("Error: could not open the directory");
        return NULL;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == 8 && strcmp(ent->d_name, filename) == 0) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", ACCOUNTS_DIR, ent->d_name);

            FILE* file = fopen(path, "r");
            if (file == NULL) {
                perror("Error: could not open the file");
                closedir(dir);
                return NULL;
            }

            char line[256];
            while (fgets(line, sizeof(line), file) != NULL) {
                if (strncmp(line, "Balance:", 8) == 0) {
                    if (fgets(line, sizeof(line), file) != NULL) {
                        balance = strdup(line);
                        char* end;
                        double bal = strtod(balance, &end);
                        if (*end != '\n' || end == balance) {
                            free(balance);
                            balance = NULL;
                        }
                        break;
                    }
                }
            }

            fclose(file);
            break;
        }
    }

    closedir(dir);
    return balance;
}

bool transfer_feasible(char* userID, char* amount){
    char *encrypted_filename;
    encrypted_filename = malloc(2048);
    char *decrypted_filename;
    decrypted_filename = malloc(2048);
    char *balance = NULL;
    balance = malloc(2048);
                
    strcpy(encrypted_filename, "clients/accounts/");
    strcat(encrypted_filename, userID);
    strcat(encrypted_filename, ".txt.enc");
    cbc_decrypt(encrypted_filename);

    strcpy(decrypted_filename, userID);
    decrypted_filename = strcat(decrypted_filename, ".txt.enc.dec");
    balance = get_balance(decrypted_filename);
    remove(strcat(encrypted_filename, ".dec"));

    if (balance != NULL && amount != NULL) {
        double difference = atof(balance) - atof(amount);
        if (difference < 0) {
            return false;
        }
    } else {
        printf("Error: Invalid balance.\n");
        return false;
    }

    return true;
}

bool check_user(char* username) {
    FILE* passwords_file = fopen("clients/passwords/userID.txt", "r");
    if (passwords_file == NULL) {
        printf("Error: could not open passwords file.\n");
        return false;
    }

    char line[100];
    while (fgets(line, sizeof(line), passwords_file) != NULL) {
        char* token = strtok(line, " -- ");
        if (token != NULL && username != NULL) {
            if (strcmp(token, username) == 0) {
                fclose(passwords_file);
                return true;
            }
        } else {
            printf("Error: Invalid line or username.\n");
            fclose(passwords_file);
            return false;
        }
    }

    fclose(passwords_file);
    return false;
}

void update_balance_sender(char* filename, char* amount) {
    char path[1024];
    snprintf(path, sizeof(path), "clients/accounts/%s", filename);
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "clients/accounts/temp_%s", filename);
    
    FILE* file = fopen(path, "r");
    FILE* temp_file = fopen(temp_path, "w");

    if (file == NULL || temp_file == NULL) {
        perror("Error: could not open file");
        return;
    }

    char *balance = NULL;
    balance = malloc(2048 * sizeof(char));
    balance = get_balance(filename);

    double updated_balance = 0.0;
    updated_balance = atof(balance) - atof(amount);

    char buffer[2048];
    char replace[2048];
    snprintf(replace, sizeof(replace), "%f\n", updated_balance);


    int replace_line = 2; 
    int current_line = 1;

 
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (current_line == replace_line) {
            fputs(replace, temp_file);
        } else {
            fputs(buffer, temp_file);
        }
        current_line++;
    }

    fclose(file);
    fclose(temp_file);
    remove(path);
    rename(temp_path, path);
}

void update_balance_receiver(char* filename, char* amount) {
    char path[1024];
    snprintf(path, sizeof(path), "clients/accounts/%s", filename);
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "clients/accounts/temp_%s", filename);
    
    FILE* file = fopen(path, "r");
    FILE* temp_file = fopen(temp_path, "w");

    if (file == NULL || temp_file == NULL) {
        perror("Error: could not open file");
        return;
    }

    char *balance = NULL;
    balance = malloc(2048 * sizeof(char));
    balance = get_balance(filename);

    double updated_balance = 0.0;
    updated_balance = atof(balance) + atof(amount);

    char buffer[2048];
    char replace[2048];
    snprintf(replace, sizeof(replace), "%f\n", updated_balance);


    int replace_line = 2; 
    int current_line = 1;

 
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (current_line == replace_line) {
            fputs(replace, temp_file);
        } else {
            fputs(buffer, temp_file);
        }
        current_line++;
    }

    fclose(file);
    fclose(temp_file);
    remove(path);
    rename(temp_path, path);
}

void update_history_sender(char* filename, char* beneficiary, char* amount) {
    char path[512];
    snprintf(path, sizeof(path), "clients/accounts/%s", filename);

    FILE* file = fopen(path, "a");
    if (file == NULL) {
        perror("Error: could not open file");
        return;
    }

    char* new_line = NULL;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char line[256];

    strftime(line, sizeof(line), "%Y-%m-%d %H:%M:%S", tm_info);

    new_line = calloc(2048, sizeof(char));

    strcat(new_line, "\n");
    strcat(new_line, beneficiary);
    strcat(new_line, " -- -");
    strcat(new_line, amount);
    strcat(new_line, " -- ");
    strcat(new_line, line);

    fprintf(file, "%s", new_line);

    fclose(file);
    free(new_line);
}

void update_history_receiver(char* filename, char* username, char* amount) {
    char path[512];
    snprintf(path, sizeof(path), "clients/accounts/%s", filename);

    FILE* file = fopen(path, "a");
    if (file == NULL) {
        perror("Error: could not open file");
        return;
    }

    char* new_line = NULL;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char line[256];

    strftime(line, sizeof(line), "%Y-%m-%d %H:%M:%S", tm_info);

    new_line = calloc(2048, sizeof(char));
    strcat(new_line, "\n");
    strcat(new_line, username);
    strcat(new_line, " -- +");
    strcat(new_line, amount);
    strcat(new_line, " -- ");
    strcat(new_line, line);

    fprintf(file, "%s", new_line);

    fclose(file);
    free(new_line);
}

char* get_history(char* filename) {
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "clients/accounts/%s", filename);

    FILE* file = fopen(filepath, "r");
    if (file == NULL) {
        printf("Error: could not open the file %s\n", filepath);
        return NULL;
    }

    char buffer[1024];
    int history_found = 0;
    char* history = NULL;
    size_t history_size = 0;

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (history_found) {
            size_t line_length = strlen(buffer);
            history = realloc(history, history_size + line_length + 1);
            strncpy(history + history_size, buffer, line_length);
            history_size += line_length;
            history[history_size] = '\0';
        }
        else if (strncmp(buffer, "History:", 8) == 0) {
            history_found = 1;
        }
    }

    fclose(file);
    return history;
}

void handleErrors(){
    fprintf(stderr, "An error occured.\n");
    exit(1);
}
 
void printHex(unsigned char *data, size_t size){
    for (size_t i = 0; i < size; ++i)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
} 

void printPublicKey(const BIGNUM *publicKey){
    char *hexPublicKey = BN_bn2hex(publicKey);
    printf("%s\n", hexPublicKey);
    OPENSSL_free(hexPublicKey);
}

char* convertToHex(const unsigned char* data, int data_len) {
    char* hex_str = (char*)malloc((data_len * 2 + 1) * sizeof(char));
    if (hex_str == NULL) {
        fprintf(stderr, "Error: could not allocate memory.\n");
        exit(1);
    }

    for (int i = 0; i < data_len; i++) {
        sprintf(hex_str + (i * 2), "%02x", data[i]);
    }

    hex_str[data_len * 2] = '\0';  // Ajout du caractère nul à la fin de la chaîne hexadécimale

    return hex_str;
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

/***********************************END OF AUXILIARY FUNCTIONS*****************************************************/




/***********************************BEGIN OF MAIN FUNCTION OF THE SERVER*****************************************************/

int main(int argc, char *argv[]) {

    /*Creation of the TCP connection:*/
    char *ip = "127.0.0.1";
    int port = 5931;

    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size;
    char buffer[1024];
    int n;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0){
        perror("Socket error.");
        exit(1);
    } 

    printf("TCP server socket is created. \n");
    int optval = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;

    n = bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (n < 0){
        perror("Bind error.");
        exit(1);
    }

    printf("Bind to the port number: %d\n", port);

    listen(server_sock, 5);
    printf("Waiting for client...\n");

    

    /*Main loop:*/
    while(1){
        addr_size = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_size);


        char *username = malloc(2048 * sizeof(char));

/* ***********************************BEGIN OF AUTHENTICATION PROTOCOL**************************************************** */

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

        DH *server_params = DH_new();
        DH_set0_pqg(server_params, p, NULL, g);

        if (DH_generate_key(server_params) != 1){
            fprintf(stderr, "Error: could not generate keys for the server.\n");
            handleErrors();
        }

        /*Reception of Yb (client's DH public key for the protocol):*/
        char Yb_hex[513];
        memset(Yb_hex, 0, sizeof(Yb_hex));

        int bytes_received = recv(client_sock, Yb_hex, sizeof(Yb_hex) - 1, 0);
        if (bytes_received == -1) {
            fprintf(stderr, "Error: could not receive Yb.\n");
            handleErrors();
        }
        Yb_hex[bytes_received] = '\0'; 
        
        BIGNUM *Yb = BN_new();
        if (BN_hex2bn(&Yb, Yb_hex) == 0) {
            fprintf(stderr, "Error: could not convert Yb in BIGNUM.\n");
            BN_free(p);
            BN_free(g);
            handleErrors();
        }

        /*Computing Ya (bank's DH public key for the protocol):*/
        BIGNUM *Ya = BN_new();
        const BIGNUM *a = NULL;
        a = DH_get0_priv_key(server_params);
        BN_mod_exp(Ya, g, a, p, BN_CTX_secure_new());
        size_t Ya_size = BN_num_bytes(Ya);


        /*Sending Ya to the client:*/
        char *Ya_hex = BN_bn2hex(Ya);
        int bytes_sent = send(client_sock, Ya_hex, Ya_size*2, 0);
        if (bytes_sent == -1 || bytes_sent != Ya_size*2){
            fprintf(stderr, "Error: could not send Ya.\n");
            free(Ya_hex);
            handleErrors();
        }

        /*Computing the secret key:*/
        BIGNUM *session_key = BN_new();
        BN_mod_exp(session_key, Yb, a, p, BN_CTX_secure_new());
        char *secret_key = BN_bn2hex(session_key);
        BN_free(session_key);


        /**********FROM NOW ON COMMUNICATIONS ARE ENCRYPTED:**********/

        /*AUTHENTICATION OF THE BANK:*/
        /*Computing Yb || Ya:*/
        BIGNUM *Yb_Ya = BN_new();
        Yb_Ya = concatenateBIGNUMs(Yb, Ya);
        size_t Yb_Ya_size = BN_num_bytes(Yb_Ya);

        /*Loading the bank's private key to perform the digital signature:*/
        EVP_PKEY *bank_private_key = NULL;
        char private_key_file_path[100];
        sprintf(private_key_file_path, "bank/private_key.txt");
        FILE *bank_private_key_file = fopen(private_key_file_path, "r");
        if (bank_private_key_file == NULL){
            fprintf(stderr, "Error: could not open bank's private key file.\n");
            handleErrors();
        }
        bank_private_key = PEM_read_PrivateKey(bank_private_key_file, NULL, NULL, NULL);
        fclose(bank_private_key_file);
        if (bank_private_key == NULL){
            fprintf(stderr, "Error: could not load the private key.\n");
            handleErrors();
        }

        int Yb_Ya_bin_size = BN_num_bytes(Yb_Ya);
        unsigned char *Yb_Ya_bin = (unsigned char *)malloc(Yb_Ya_bin_size);
        if (Yb_Ya_bin == NULL){
            fprintf(stderr, "Error: could not allocate memory for Yb || Ya.\n");
            BN_free(p);
            BN_free(g);
            BN_free(Yb_Ya);
            handleErrors();
        }

        BN_bn2bin(Yb_Ya, Yb_Ya_bin);

        /*Signature:*/
        EC_KEY *bank_ec_key_sign = EVP_PKEY_get1_EC_KEY(bank_private_key);
        if (bank_ec_key_sign == NULL){
            fprintf(stderr, "Error: could not retrieve the private key to perform the signature.\n");
            free(Yb_Ya_bin);
            EVP_PKEY_free(bank_private_key);
            handleErrors();
        }

        EC_GROUP *ec_group = (EC_GROUP *)EC_KEY_get0_group(bank_ec_key_sign);

        ECDSA_SIG *signature = ECDSA_do_sign(Yb_Ya_bin, Yb_Ya_bin_size, bank_ec_key_sign);
        if (signature == NULL){
            fprintf(stderr, "Error: could not compute the digital signature of Yb || Ya.\n");
            free(Yb_Ya_bin);
            EC_KEY_free(bank_ec_key_sign);
            EVP_PKEY_free(bank_private_key);
            handleErrors();
        }

        unsigned char *sig_Yb_Ya = NULL;
        int sig_Yb_Ya_size = i2d_ECDSA_SIG(signature, &sig_Yb_Ya);
        if (sig_Yb_Ya_size <= 0){
            fprintf(stderr, "Error: could not convert signature in format DER.\n");
            free(Yb_Ya_bin);
            ECDSA_SIG_free(signature);
            EC_KEY_free(bank_ec_key_sign);
            EVP_PKEY_free(bank_private_key);
            handleErrors();
        }

        /*Sending the signature to the client:*/
        char* sig_Yb_Ya_hex = convertToHex(sig_Yb_Ya, sig_Yb_Ya_size);

        int bytes_sent_sig = send(client_sock, gcm_encrypt(sig_Yb_Ya_hex, secret_key), strlen(sig_Yb_Ya_hex) + NONCE_SIZE + sizeof(int), 0);
        if (bytes_sent_sig == -1 || bytes_sent_sig != strlen(sig_Yb_Ya_hex) + NONCE_SIZE + sizeof(int)) {
        fprintf(stderr, "Error: could not send the digital signature to the client.\n");
            free(Yb_Ya_bin);
            ECDSA_SIG_free(signature);
            EC_KEY_free(bank_ec_key_sign);
            EVP_PKEY_free(bank_private_key);
            handleErrors();
        }


        /*AUTHENTICATION OF THE CLIENT:*/
        char* encrypted_username = malloc(2048);
        int received_bytes_encrypted_username = recv(client_sock, encrypted_username, 2048, 0);
        if (received_bytes_encrypted_username > 0) {
            username = gcm_decrypt(encrypted_username, secret_key);
            free(encrypted_username);
        }

        if(!check_user(username)){
            char wrong[] = "Wrong";
            send(client_sock, gcm_encrypt(wrong, secret_key), strlen(wrong) + NONCE_SIZE + sizeof(int), 0);
            shutdown(client_sock, SHUT_RDWR);
            close(client_sock);
            close(server_sock);
            exit(1);
        } else {
            char right[] = "Right";
            send(client_sock, gcm_encrypt(right, secret_key), strlen(right) + NONCE_SIZE + sizeof(int), 0);
        }


        /*Checking password:*/
        bool password_check = false;
        while (!password_check) {
            char* password = malloc(2048);
            char* encrypted_password = malloc(2048);
            int received_bytes_encrypted_password = recv(client_sock, encrypted_password, 2048, 0);
            if (received_bytes_encrypted_password > 0) {
                password = gcm_decrypt(encrypted_password, secret_key);
                free(encrypted_username);
            }

            if (!check_password(username, password)) {
                char wrong[] = "Wrong";
                send(client_sock, gcm_encrypt(wrong, secret_key), strlen(wrong) + NONCE_SIZE + sizeof(int), 0);
            } else {
                char right[] = "Right";
                send(client_sock, gcm_encrypt(right, secret_key), strlen(right) + NONCE_SIZE + sizeof(int), 0);
            }

            char* password_response = malloc(2048);
            char* encrypted_password_response = malloc(2048);
            int received_bytes_encrypted_password_response = recv(client_sock, encrypted_password_response, 2048, 0);
            if (received_bytes_encrypted_password_response > 0) {
                password_response = gcm_decrypt(encrypted_password_response, secret_key);
                free(encrypted_password_response);
            }

            if (strcmp(password_response, "Stop") == 0) {
                password_check = true;
            } else if (strcmp(password_response, "Count") == 0) {
                free(password);
                free(password_response);
                shutdown(client_sock, SHUT_RDWR);
                close(client_sock);
                close(server_sock);
                exit(1);
            }

            free(password);
            free(password_response);
        }
        
        /*Free the memory BUT KEEP the secret key:*/
        DH_free(server_params);
        free(Ya_hex);
        free(Yb_Ya_bin);
        ECDSA_SIG_free(signature);
        EC_KEY_free(bank_ec_key_sign);
        EVP_PKEY_free(bank_private_key);

/***********************************END OF AUTHENTICATION PROTOCOL*****************************************************/

        
/***********************************BEGIN OF BANKING'S OPERATIONS*****************************************************/

        char *userID = remove_spaces(get_ID(username));
        char *operation = malloc(2048 * sizeof(char));

        while (strcmp(operation, "leave the application") != 0){

            /*Operations to perform:*/
            char *encrypted_operation = malloc(2048);
            int received_bytes_encrypted_operation = recv(client_sock, encrypted_operation, 2048, 0);
            if (received_bytes_encrypted_operation > 0) {
                operation = gcm_decrypt(encrypted_operation, secret_key);
                free(encrypted_operation);
            }
            

            /*Balance:*/
            if ((strcmp(operation, "check his balance") == 0)){
                char *encrypted_filename = malloc(2048);
                char *decrypted_filename = malloc(2048);
                char *balance = malloc(2048);
                
                send(client_sock, gcm_encrypt(userID, secret_key), strlen(userID) + NONCE_SIZE + sizeof(int), 0);

                strcpy(encrypted_filename, "clients/accounts/");
                strcat(encrypted_filename, userID);
                strcat(encrypted_filename, ".txt.enc");
                cbc_decrypt(encrypted_filename);

                strcpy(decrypted_filename, userID);
                decrypted_filename = strcat(decrypted_filename, ".txt.enc.dec");
                balance = get_balance(decrypted_filename);
                remove(strcat(encrypted_filename, ".dec"));

                send(client_sock, gcm_encrypt(balance, secret_key), strlen(balance) + NONCE_SIZE + sizeof(int), 0);
                free(balance);

            /*Transfer:*/
            } else if ((strcmp(operation, "make a transfer") == 0)){
                char *beneficiary = malloc(2048);
                char *encrypted_beneficiary = malloc(2048);
                int received_bytes_encrypted_beneficiary = recv(client_sock, encrypted_beneficiary, 2048, 0);
                if (received_bytes_encrypted_beneficiary > 0) {
                    beneficiary = gcm_decrypt(encrypted_beneficiary, secret_key);
                    free(encrypted_beneficiary);
                }

                char *amount = malloc(2048);
                char *encrypted_amount = malloc(2048);
                int received_bytes_encrypted_amount = recv(client_sock, encrypted_amount, 2048, 0);
                if (received_bytes_encrypted_amount > 0) {
                    amount = gcm_decrypt(encrypted_amount, secret_key);
                    free(encrypted_amount);
                }

                beneficiary = remove_spaces(beneficiary);
                amount = remove_spaces(amount);

                bool possible = (transfer_feasible(userID, amount) && check_user(beneficiary) && contains_double(amount));

                

                if (possible) {
                    char *encrypted_beneficiray_filename = malloc(2048);
                    char *init_user_file = malloc(2048);
                    char *decrypted_user_filename = malloc(2048);
                    char *encrypted_user_filename = malloc(2048);
                    char *init_beneficiary_file = malloc(2048);
                    char *decrypted_beneficiray_filename = malloc(2048);

                    strcpy(encrypted_user_filename, "clients/accounts/");
                    strcat(encrypted_user_filename, userID);
                    strcat(encrypted_user_filename, ".txt.enc");
                    strcpy(init_user_file, encrypted_user_filename);
                    cbc_decrypt(encrypted_user_filename);

                    strcpy(decrypted_user_filename, userID);
                    decrypted_user_filename = strcat(decrypted_user_filename, ".txt.enc.dec");
                    update_history_sender(decrypted_user_filename, beneficiary, amount);
                    update_balance_sender(decrypted_user_filename, amount);
                    cbc_encrypt(strcat(encrypted_user_filename, ".dec"));
                    remove(encrypted_user_filename);
                    rename(strcat(encrypted_user_filename,".enc"), init_user_file);


                    strcpy(encrypted_beneficiray_filename, "clients/accounts/");
                    strcat(encrypted_beneficiray_filename, remove_spaces(get_ID(beneficiary)));
                    strcat(encrypted_beneficiray_filename, ".txt.enc");
                    strcpy(init_beneficiary_file, encrypted_beneficiray_filename);
                    cbc_decrypt(encrypted_beneficiray_filename);
 
                    strcpy(decrypted_beneficiray_filename, remove_spaces(get_ID(beneficiary)));
                    decrypted_beneficiray_filename = strcat(decrypted_beneficiray_filename, ".txt.enc.dec");
                    update_history_receiver(decrypted_beneficiray_filename, username, amount);
                    update_balance_receiver(decrypted_beneficiray_filename, amount);
                    cbc_encrypt(strcat(encrypted_beneficiray_filename, ".dec"));
                    remove(encrypted_beneficiray_filename);
                    rename(strcat(encrypted_beneficiray_filename,".enc"), init_beneficiary_file);

                    char success[] = "Succes!\n";
                    send(client_sock, gcm_encrypt(success, secret_key), strlen(success) + NONCE_SIZE + sizeof(int), 0);

                } else {
                    char fail[] = "Fail\n";
                    send(client_sock, gcm_encrypt(fail, secret_key), strlen(fail) + NONCE_SIZE + sizeof(int), 0);
                }

                free(amount);
                free(beneficiary);
                
            /*History:*/
            } else if ((strcmp(operation, "check his history") == 0)){
                char *encrypted_filename = malloc(2048);
                char *decrypted_filename = malloc(2048);
                char *history = malloc(2048);

                strcpy(encrypted_filename, "clients/accounts/");
                strcat(encrypted_filename, userID);
                strcat(encrypted_filename, ".txt.enc");
                cbc_decrypt(encrypted_filename);

                strcpy(decrypted_filename, userID);
                decrypted_filename = strcat(decrypted_filename, ".txt.enc.dec");
                history = get_history(decrypted_filename);
                remove(strcat(encrypted_filename, ".dec"));
                if (history != NULL) {
                    send(client_sock, gcm_encrypt(history, secret_key), strlen(history) + NONCE_SIZE + sizeof(int), 0);
                } else {
                    char no_transaction[] = "No transaction yet.";
                    send(client_sock, gcm_encrypt(no_transaction, secret_key), strlen(no_transaction) + NONCE_SIZE + sizeof(int), 0);
                }
                free(history);
            }
            
        }

/***********************************END OF BANKING'S OPERATIONS*****************************************************/


        shutdown(client_sock, SHUT_RDWR);
        close(client_sock);
        free(userID);
        free(operation);
        free(secret_key);
        free(username);
        break;
    }

    close(server_sock);
    return 0;
}

/***********************************END OF MAIN FUNCTION OF THE SERVER*****************************************************/