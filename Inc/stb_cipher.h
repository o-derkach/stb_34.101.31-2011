#ifndef STB_CIPHER_H_
#define STB_CIPHER_H_

extern const uint32_t sub_1[256];

// if round = 0 - no fault
void cryptWithFault(const uint32_t *in, const uint32_t *key, uint32_t *out, const int round, const int position);
void crypt_yasv(const uint32_t *in, const uint32_t *key, uint32_t *out);

#endif /* STB_CIPHER_H_ */
