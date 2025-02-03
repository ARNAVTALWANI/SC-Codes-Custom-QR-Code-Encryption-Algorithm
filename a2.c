#include "a2.h"

int bitwise_xor(int value){
    return value ^ KEY;
}

char *xor_encrypt(char c){
    int xor_result = bitwise_xor(c);
    char *bin_str = (char *)malloc(8 * sizeof(char)); //Allocating memory for 8 characters

    if (!bin_str) { //Memory allocation failed
        return NULL;
    }

    bin_str[7] = '\0'; //Null-terminating the string

    for (int i = 6; i >= 0; i--) { //Converting the decimal int to binary
        bin_str[i] = xor_result % 2 + '0';
        xor_result /= 2;
    }

    return bin_str;
}

char xor_decrypt(char *s){
    int val = 0;

    for (int i = 0; i < 7; i++) { //Converting the binary string to decimal
        val += (s[i] - '0') * pow(2, 6 - i);
    }

    return bitwise_xor(val);
}

char *gen_code(char *msg){
    int len = strlen(msg);
    char *code = (char *)malloc(257 * sizeof(char)); //Allocating memory for the binary string

    if (!code) { //Memory allocation failed
        return NULL;
    }

    code[0] = '\0'; //Null-terminating the string

    for (int i = 0; i < len; i++) { //Encrypting each character in the message
        char* encrypted_char = xor_encrypt(msg[i]);
        if (encrypted_char) {
            strcat(code, encrypted_char);
            free(encrypted_char);
        }
    }

    for (int i = strlen(code); i < 256; i++) { //Padding the string with zeros
        code[i] = '0';
    }
    code[256] = '\0'; //Null-terminating the string

    return code;
}

char *read_code(char *code){
    int num_chars = strlen(code) / 8;
    char *msg = (char *)malloc(num_chars * sizeof(char) + 1); //Allocating memory for the message

    if (!msg) { //Memory allocation failed
        return NULL;
    }

    char segment[9]; //Buffer for each 8-bit segment
    int index = 0;

    for (int i = 0; i < num_chars; i++) { //Decrypting each 8-bit segment
        strncpy(segment, code + i * 8, 7);
        segment[7] = '\0';
        msg[index++] = xor_decrypt(segment);
    }
    msg[num_chars] = '\0'; //Null-terminating the string

    return msg;
}

char *compress(char *code){
    int num_hex_chars = 256/4;
    char* hex_str = (char *)malloc(num_hex_chars * sizeof(char) + 1); //Allocating memory for the hexadecimal string

    if (!hex_str) { //Memory allocation failed
        return NULL;
    }

    hex_str[num_hex_chars] = '\0'; //Null-terminating the string

    char buffer[5]; //Buffer for each 4-bit segment
    buffer[4] = '\0';
    int hex_val;

    for (int i = 0; i < num_hex_chars; i++) { //Converting each 4-bit segment to hexadecimal
        strncpy(buffer, code + i * 4, 4);
        hex_val = strtol(buffer, NULL, 2);
        
        if (hex_val < 10) {
            hex_str[i] = hex_val + '0';
        } else {
            hex_str[i] = hex_val - 10 + 'A';
        }
    }

    hex_str[num_hex_chars] = '\0'; //Null-terminating the string
    return hex_str;
}

char *decompress(char *code){
    int num_hex_chars = 64;
    int num_bin_chars = 256;
    char* bin_str = (char *)malloc(num_bin_chars * sizeof(char) + 1); //Allocating memory for the binary string

    if (!bin_str) { //Memory allocation failed
        return NULL;
    }

    bin_str[num_bin_chars] = '\0'; //Null-terminating the string

    for (int i = 0; i < num_hex_chars; i++) { //Converting each hexadecimal character to 4-bit binary
        int hex_val;
        if (code[i] >= '0' && code[i] <= '9') {
            hex_val = code[i] - '0';
        } else if (code[i] >= 'A' && code[i] <= 'F') {
            hex_val = code[i] - 'A' + 10;
        } else if (code[i] >= 'a' && code[i] <= 'f') {
            hex_val = code[i] - 'a' + 10;
        } else {
            free(bin_str);
            return NULL;
        }
        for (int j = 0; j < 4; j++) {
            bin_str[i * 4 + (3 - j)] = (hex_val & (1 << j)) ? '1' : '0';
        }
    }

    return bin_str;
}

int calc_ld(char *sandy, char *cima){
    int len_sandy = strlen(sandy);
    int len_cima = strlen(cima);
    int **dp = (int **)malloc((len_sandy + 1) * sizeof(int *)); //Allocating memory for the 2D array

    if (!dp) { //Memory allocation failed
        return -1;
    }

    for (int i = 0; i <= len_sandy; i++) {
        dp[i] = (int *)malloc((len_cima + 1) * sizeof(int));
        if (!dp[i]) { //Memory allocation failed
            for (int j = 0; j < i; j++) {
                free(dp[j]);
            }
            free(dp);
            return -1;
        }
    }

    for (int i = 0; i <= len_sandy; i++) {
        for (int j = 0; j <= len_cima; j++) {
            if (i == 0) {
                dp[i][j] = j;
            } else if (j == 0) {
                dp[i][j] = i;
            } else if (sandy[i - 1] == cima[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + fmin(fmin(dp[i - 1][j], dp[i][j - 1]), dp[i - 1][j - 1]);
            }
        }
    }

    int ld = dp[len_sandy][len_cima];

    for (int i = 0; i <= len_sandy; i++) {
        free(dp[i]);
    }
    free(dp);

    return ld;
}