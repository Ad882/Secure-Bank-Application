#include <stddef.h>

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#ifdef __cplusplus
extern "C" {
#endif


char* gcm_encrypt(char* plaintext, unsigned char* secret_key); 

char* gcm_decrypt(char* ciphertext, unsigned char* secret_key);

char* cbc_encrypt(char* clear_file_name);

char* cbc_decrypt(char* cphr_file_name);

char* sha256_hash(const char* data, const char* salt);


#ifdef __cplusplus
}
#endif

#endif
