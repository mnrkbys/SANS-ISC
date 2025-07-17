#include <sys/xattr.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Base64 character set
const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//
// Decode a Base64 chunk
// Source: https://raw.githubusercontent.com/realapire/base64-encode-decode/refs/heads/master/base64.c
//
unsigned char *base64_decode(const char *input, size_t *output_length) {
    size_t input_length = strlen(input);
    if (input_length % 4 != 0) {
        return NULL; // Invalid Base64 input length
    }

    // Calculate the expected output length
    *output_length = (3 * input_length) / 4;
    if (input[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (input[input_length - 2] == '=') {
        (*output_length)--;
    }

    // Allocate memory for the decoded data
    unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL; // Memory allocation failed
    }

    // Initialize variables for decoding process
    size_t j = 0;
    uint32_t sextet_bits = 0;
    int sextet_count = 0;

    // Loop through the Base64 input and decode it
    for (size_t i = 0; i < input_length; i++) {
        // Convert Base64 character to a 6-bit value
        uint32_t base64_value = 0;
        if (input[i] == '=') {
            base64_value = 0;
        } else {
            const char *char_pointer = strchr(base64_chars, input[i]);
            if (char_pointer == NULL) {
                free(decoded_data);
                return NULL; // Invalid Base64 character
            }
            base64_value = char_pointer - base64_chars;
        }

        // Combine 6-bit values into a 24-bit sextet
        sextet_bits = (sextet_bits << 6) | base64_value;
        sextet_count++;

        // When a sextet is complete, decode it into three bytes
        if (sextet_count == 4) {
            decoded_data[j++] = (sextet_bits >> 16) & 0xFF;
            decoded_data[j++] = (sextet_bits >> 8) & 0xFF;
            decoded_data[j++] = sextet_bits & 0xFF;
            sextet_bits = 0;
            sextet_count = 0;
        }
    }

    return decoded_data;
}

static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file1> [file2 …]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *attr_name = "user.payload";
    uint8_t xor_key       = 0xFB;

    for (int i = 1; i < argc; ++i) {
        const char *src = argv[i];

        ssize_t size64 = getxattr(src, attr_name, NULL, 0);
        if (size64 == -1) {
            fprintf(stderr, "Skip '%s': no '%s' (%s)\n", src, attr_name, strerror(errno));
            continue;
        }

        char *buf64 = malloc(size64 + 1);
        if (!buf64) die("malloc buf64");

        ssize_t r = getxattr(src, attr_name, buf64, size64);
        if (r == -1) {
            fprintf(stderr, "Skip '%s': read error (%s)\n", src, strerror(errno));
            free(buf64); continue;
        }
        buf64[r] = '\0';

        /* Base64 decode */
        size_t raw_len;
        unsigned char *raw = base64_decode(buf64, &raw_len);
        free(buf64);
        if (!raw) die("b64_decode");

        /* XOR decrypt in place */
        for (size_t j = 0; j < raw_len; ++j) 
            raw[j] ^= xor_key;

	printf("%s", raw);

        free(raw);
    }

    return EXIT_SUCCESS;
}
