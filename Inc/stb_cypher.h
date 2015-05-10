#ifndef SUBSTITUTION_H_
#define SUBSTITUTION_H_

#include "utils.h"

void crypt(const uint32_t *in, const uint32_t *key, uint32_t *out);
void crypt_yasv(const uint32_t *in, const uint32_t *key, uint32_t *out);

#endif /* SUBSTITUTION_H_ */
