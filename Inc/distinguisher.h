#ifndef DISTINGUISHER_H_
#define DISTINGUISHER_H_

#define MAX_REPEAT_NUM 256
#define MAX_KEYS_NUM 1

void handDistinguisher();
void autoDistinguisher();
void autoDistinguisher_5();

typedef struct {
	int bytes[4];
} Results;

#endif /* DISTINGUISHER_H_ */
