/*
 * Header for different configuration parameters of the system
 */
#ifndef CONFIG_H_
#define CONFIG_H_

#define BLOCK_BIT_LEN 128
#define BLOCK_BYTE_LEN BLOCK_BIT_LEN / 8
#define BLOCK_WORD_LEN BLOCK_BIT_LEN / 32
#define SBLOCK_VAL_COUNT 256

#define KEY_BIT_LEN 256
#define KEY_BYTE_LEN KEY_BIT_LEN / 8
#define KEY_WORD_LEN KEY_BIT_LEN / 32

#define ROUND_NUM 8
#define ROUNDKEY_NUM 56
#define ROUNDKEY_BIT_LEN 32

#define MAX_TEXT_NUM 10000

#endif /* CONFIG_H_ */
