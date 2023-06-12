#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "encryption.h"

/************************************BEGIN OF AUXILIARY FUNCTIONS*****************************************************/


bool check_user(const char* username) {/*To check if the username is already used*/
    FILE* passwords_file = fopen("clients/passwords/passwords.txt", "r");
    if (passwords_file == NULL) {
        printf("Failed to open passwords file for reading.\n");
        return false;
    }

    char line[100];
    while (fgets(line, sizeof(line), passwords_file) != NULL) {
        char* token = strtok(line, " -- ");
        if (token != NULL && strcmp(token, username) == 0) {
            fclose(passwords_file);
            return false; 
        }
    }

    fclose(passwords_file);
    return true;  
}

void createDirectory(char* directoryName) {/*To create the directory where the user stores his keys*/
    char path[100] = "users/";
    strcat(path, directoryName);
    int result = mkdir(path, 0777);

    if (result != 0) {
        printf("Impossible to create the directory %s.\n", path);
    }
}

void generate_salt(const char* username) {
    const int SALT_LENGTH = 16;
    const char* salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    char salt[SALT_LENGTH + 1];
    srand(time(NULL));
    for (int i = 0; i < SALT_LENGTH; ++i) {
        salt[i] = salt_chars[rand() % strlen(salt_chars)];
    }
    salt[SALT_LENGTH] = '\0';

    FILE* salt_file = fopen("clients/passwords/salts.txt", "a");
    if (salt_file != NULL) {
        fprintf(salt_file, "%s -- %s\n", username, salt);
        fclose(salt_file);
        printf("Salt generated and saved successfully.\n");
    } else {
        printf("Failed to open salts file.\n");
    }
}

char* get_salt(char* username) {
    char path[256];
    char line[1024];
    char* token;
    char* salt = NULL;

    FILE *fp = fopen("clients/passwords/salts.txt","r"); 

    if (fp == NULL) {
        perror("Error opening file");
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

/************************************END OF AUXILIARY FUNCTIONS*****************************************************/

 
 
int main() {
    srand(time(NULL));
    bool check = false;
    char username[1024];
    char password[1024];

    while (!check){
        bool length = false;
        printf("Please enter username: ");
        scanf("%s", username);
        printf("Please enter password: ");
        scanf("%s", password);

        length = ((strlen(password) >= 5));

        /*If the username is not already chosen and the password is long enough, the registration is completed:*/
        if (check_user(username) && length){

            /*Generation of the userID:*/
            long int user_id = rand() % 9000000000 + 10000000000L;
            if (user_id < 0 ){
                user_id = -user_id;
            }

            /*Generation and storage of the salt:*/
            generate_salt(username);

            /*Registration of the user in the bank's files:*/
            FILE *passwords_file = fopen("clients/passwords/passwords.txt", "a");
            if (passwords_file == NULL) {
                printf("Failed to open passwords file for writing.\n");
                return 1;
            }

            FILE *id_file = fopen("clients/passwords/userID.txt", "a");
            if (id_file == NULL) {
                printf("Failed to open ID file for writing.\n");
                fclose(passwords_file);
                return 1;
            }
            
            fprintf(passwords_file, "%s\n", sha256_hash(password, get_salt(username)));
            fprintf(id_file, "%s -- %ld\n", username, user_id);
            fclose(passwords_file);
            fclose(id_file);

            /*Verification of the directory clients/accounts:*/
            struct stat st;
            if (stat("clients/accounts", &st) == -1) {
                mkdir("clients/accounts", 0700);
            }

            /*Creation of the account file:*/
            char filename[100];
            sprintf(filename, "clients/accounts/%ld.txt", user_id);
            FILE *account_file = fopen(filename, "w");
            if (account_file == NULL) {
                printf("Failed to create account file.\n");
                return 1;
            }

            fprintf(account_file, "Balance:\n");
            fprintf(account_file, "1000\n");
            fprintf(account_file, "\n");
            fprintf(account_file, "History:");
            fclose(account_file);
            

            FILE* file = fopen("username.tmp", "w");
            if (file != NULL) {
                fprintf(file, "%s", username);
                fclose(file);
            }
        
            
            char file_extension[] = ".txt";
            char *clear_file;
            clear_file = malloc(2048);
            char ID[11];
            sprintf(ID, "%ld", user_id);
            strcpy(clear_file, "clients/accounts/");
            strcat(clear_file, ID);
            strcat(clear_file, file_extension);
            cbc_encrypt(clear_file);
            remove(clear_file);
            free(clear_file);
            
            printf("User registered successfully. ID: %ld\n", user_id);
            check = true;

        } else {
            printf("Sorry, username or password not valid. Please try another one.\n");
            printf("Please make sure your password is long enough (at least 5 characters).\n");
        }

    }  

    return 0;
}