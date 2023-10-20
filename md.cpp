#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

void md5Hash(const char *message, char *digest) {
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, message, strlen(message));
    MD5_Final(digest, &context);
}

int main() {
    const char *message = "Hello, MD5!";
    char digest[MD5_DIGEST_LENGTH]; // 16 bytes for MD5

    md5Hash(message, digest);

    printf("MD5 Hash: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}

