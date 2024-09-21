/*
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h> // Required for snprintf

#include <TrezorCrypto/bip39.h>
#include <TrezorCrypto/bip39_english.h>
#include <TrezorCrypto/hmac.h>
#include <TrezorCrypto/memzero.h>
#include <TrezorCrypto/options.h>
#include <TrezorCrypto/pbkdf2.h>
#include <TrezorCrypto/rand.h>
#include <TrezorCrypto/sha2.h>

#if USE_BIP39_CACHE

int bip39_cache_index = 0;

CONFIDENTIAL struct {
    bool set;
    char mnemonic[256];
    char passphrase[64];
    uint8_t seed[512 / 8];
} bip39_cache[BIP39_CACHE_SIZE];

void bip39_cache_clear(void) {
    memzero(bip39_cache, sizeof(bip39_cache));
    bip39_cache_index = 0;
}

#endif

// [wallet-core] Added output buffer
const char *mnemonic_generate(int strength, char *buf, int buflen) {
    if (strength % 32 || strength < 128 || strength > 256) {
        return 0;
    }
    uint8_t data[32] = {0};
    random_buffer(data, 32);
    const char *r = mnemonic_from_data(data, strength / 8, buf, buflen);
    memzero(data, sizeof(data));
    return r;
}

// [wallet-core] Added output buffer
const char *mnemonic_from_data(const uint8_t *data, int len, char *buf, int buflen) {
    if (len % 4 || len < 16 || len > 32) {
        return 0;
    }
    // [wallet-core] Check provided buffer validity and size
    if (!buf || buflen < (BIP39_MAX_WORDS * (BIP39_MAX_WORD_LENGTH + 1))) {
        return 0;
    }

    uint8_t bits[32 + 1] = {0};

    sha256_Raw(data, len, bits);
    // Checksum
    bits[len] = bits[0];
    // Data
    memcpy(bits, data, len);

    int mlen = len * 3 / 4;

    int i = 0, j = 0, idx = 0;
    char *p = buf; // [wallet-core]
    for (i = 0; i < mlen; i++) {
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        
        // Use snprintf to prevent buffer overflow
        int written = snprintf(p, buflen - (p - buf), "%s", wordlist[idx]);
        if (written < 0 || written >= buflen - (p - buf)) {
            // Error handling: buffer was exceeded
            return NULL;
        }
        p += written;

        // Add space or terminate the string
        if (i < mlen - 1) {
            if ((p - buf) < buflen - 1) {
                *p = ' ';
                p++;
                *p = '\0';
            } else {
                // Error handling: no space to add a space character
                return NULL;
            }
        } else {
            *p = '\0';
        }
    }
    memzero(bits, sizeof(bits));

    return buf; // [wallet-core]
}

int mnemonic_to_bits(const char *mnemonic, uint8_t *bits) {
    if (!mnemonic) {
        return 0;
    }

    uint32_t i = 0, n = 0;

    while (mnemonic[i]) {
        if (mnemonic[i] == ' ') {
            n++;
        }
        i++;
    }
    n++;

    // Check number of words
    // [wallet-core] also accept 15- and 21-word
    if (n != 12 && n != 15 && n != 18 && n != 21 && n != 24) {
        return 0;
    }

    char current_word[10] = {0};
    uint32_t j = 0, k = 0, ki = 0, bi = 0;
    uint8_t result[32 + 1] = {0};

    memzero(result, sizeof(result));
    i = 0;
    while (mnemonic[i]) {
        j = 0;
        while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
            if (j >= sizeof(current_word) - 1) {
                return 0;
            }
            current_word[j] = mnemonic[i];
            i++;
            j++;
        }
        current_word[j] = 0;
        if (mnemonic[i] != 0) {
            i++;
        }
        k = 0;
        for (;;) {
            if (!wordlist[k]) {  // Word not found
                return 0;
            }
            if (strcmp(current_word, wordlist[k]) == 0) {  // Word found at index k
                for (ki = 0; ki < 11; ki++) {
                    if (k & (1 << (10 - ki))) {
                        result[bi / 8] |= 1 << (7 - (bi % 8));
                    }
                    bi++;
                }
                break;
            }
            k++;
        }
    }
    if (bi != n * 11) {
        return 0;
    }
    memcpy(bits, result, sizeof(result));
    memzero(result, sizeof(result));

    // Returns the amount of entropy + checksum bits
    return n * 11;
}

int mnemonic_check(const char *mnemonic) {
    uint8_t bits[32 + 1] = {0};
    int mnemonic_bits_len = mnemonic_to_bits(mnemonic, bits);
    // [wallet-core] also accept 15- and 21-word
    if (mnemonic_bits_len != (12 * 11) && mnemonic_bits_len != (18 * 11) &&
        mnemonic_bits_len != (24 * 11) &&
        mnemonic_bits_len != (15 * 11) && mnemonic_bits_len != (21 * 11)) {
        return 0;
    }
    int words = mnemonic_bits_len / 11;

    uint8_t checksum = bits[words * 4 / 3];
    sha256_Raw(bits, words * 4 / 3, bits);
    if (words == 12) {
        return (bits[0] & 0xF0) == (checksum & 0xF0);  // Compare first 4 bits
    } else if (words == 15) {
        return (bits[0] & 0xF8) == (checksum & 0xF8);  // Compare first 5 bits
    } else if (words == 18) {
        return (bits[0] & 0xFC) == (checksum & 0xFC);  // Compare first 6 bits
    } else if (words == 21) {
        return (bits[0] & 0xFE) == (checksum & 0xFE);  // Compare first 7 bits
    } else if (words == 24) {
        return bits[0] == checksum;  // Compare 8 bits
    }
    return 0;
}

// Passphrase must be at most 256 characters; otherwise, it will be truncated
void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total)) {
    int mnemoniclen = strlen(mnemonic);
    int passphraselen = strnlen(passphrase, 256);
#if USE_BIP39_CACHE
    // Check cache
    if (mnemoniclen < sizeof(bip39_cache[bip39_cache_index].mnemonic) &&
        passphraselen < sizeof(bip39_cache[bip39_cache_index].passphrase)) {
        for (int i = 0; i < BIP39_CACHE_SIZE; i++) {
            if (!bip39_cache[i].set) continue;
            if (strcmp(bip39_cache[i].mnemonic, mnemonic) != 0) continue;
            if (strcmp(bip39_cache[i].passphrase, passphrase) != 0) continue;
            // Found the correct entry
            memcpy(seed, bip39_cache[i].seed, sizeof(bip39_cache[i].seed));
            return;
        }
    }
#endif
    uint8_t salt[8 + 256] = {0};
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, passphrase, passphraselen);
    CONFIDENTIAL PBKDF2_HMAC_SHA512_CTX pctx;
    pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)mnemonic, mnemoniclen, salt,
                            passphraselen + 8, 1);
    if (progress_callback) {
        progress_callback(0, BIP39_PBKDF2_ROUNDS);
    }
    for (int i = 0; i < 16; i++) {
        pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 16);
        if (progress_callback) {
            progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 16,
                              BIP39_PBKDF2_ROUNDS);
        }
    }
    pbkdf2_hmac_sha512_Final(&pctx, seed);
    memzero(salt, sizeof(salt));
#if USE_BIP39_CACHE
    // Store to cache
    if (mnemoniclen < sizeof(bip39_cache[bip39_cache_index].mnemonic) &&
        passphraselen < sizeof(bip39_cache[bip39_cache_index].passphrase)) {
        bip39_cache[bip39_cache_index].set = true;

        // Use strncpy and ensure null-termination
        strncpy(bip39_cache[bip39_cache_index].mnemonic, mnemonic, sizeof(bip39_cache[bip39_cache_index].mnemonic) - 1);
        bip39_cache[bip39_cache_index].mnemonic[sizeof(bip39_cache[bip39_cache_index].mnemonic) - 1] = '\0';

        strncpy(bip39_cache[bip39_cache_index].passphrase, passphrase, sizeof(bip39_cache[bip39_cache_index].passphrase) - 1);
        bip39_cache[bip39_cache_index].passphrase[sizeof(bip39_cache[bip39_cache_index].passphrase) - 1] = '\0';

        memcpy(bip39_cache[bip39_cache_index].seed, seed, sizeof(bip39_cache[bip39_cache_index].seed));
        bip39_cache_index = (bip39_cache_index + 1) % BIP39_CACHE_SIZE;
    }
#endif
}

// Binary search for finding the word in the wordlist
int mnemonic_find_word(const char *word) {
    int lo = 0, hi = BIP39_WORD_COUNT - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int cmp = strcmp(word, wordlist[mid]);
        if (cmp == 0) {
            return mid;
        }
        if (cmp > 0) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return -1;
}

const char *mnemonic_complete_word(const char *prefix, int len) {
    // Perform a linear search to return the first match
    for (const char *const *w = wordlist; *w != 0; w++) {
        if (strncmp(*w, prefix, len) == 0) {
            return *w;
        }
    }
    return NULL;
}

const char *mnemonic_get_word(int index) {
    if (index >= 0 && index < BIP39_WORD_COUNT) {
        return wordlist[index];
    } else {
        return NULL;
    }
}

uint32_t mnemonic_word_completion_mask(const char *prefix, int len) {
    if (len <= 0) {
        return 0x3ffffff;  // All letters (bits 1-26 set)
    }
    uint32_t res = 0;
    for (const char *const *w = wordlist; *w != 0; w++) {
        const char *word = *w;
        if (strncmp(word, prefix, len) == 0 && word[len] >= 'a' &&
            word[len] <= 'z') {
            res |= 1 << (word[len] - 'a');
        }
    }
    return res;
}
