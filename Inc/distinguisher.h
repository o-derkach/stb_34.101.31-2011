#ifndef DISTINGUISHER_H_
#define DISTINGUISHER_H_

#define MAX_REPEAT_NUM 256
#define MAX_KEYS_NUM 2

void handDistinguisher();
void autoDistinguisher();
void autoDistinguisher_2();

typedef struct {
	int bytes[4];
} Results;

#endif /* DISTINGUISHER_H_ */
