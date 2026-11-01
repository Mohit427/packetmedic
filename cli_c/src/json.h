/* json.h - small, defensive JSON parser (arena allocated, size/depth limited). */
#ifndef PM_JSON_H
#define PM_JSON_H

#include <stddef.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JVal JVal;
struct JVal {
    JType type;
    double num;           /* J_NUM, J_BOOL (0/1) */
    char *str;            /* J_STR (UTF-8, NUL-terminated) */
    char *key;            /* member name when inside an object */
    JVal *child;          /* first element / member */
    JVal *next;           /* next sibling */
    size_t len;           /* number of children */
};

typedef struct JDoc JDoc;

#define JSON_MAX_BYTES (64u * 1024u * 1024u)
#define JSON_MAX_DEPTH 64

JDoc *json_parse(const char *text, size_t len, char *err, size_t errlen);
JDoc *json_parse_file(const char *path, char *err, size_t errlen);
JVal *json_root(JDoc *d);
void  json_free(JDoc *d);

/* lookups never crash: missing/mistyped values return the fallback */
JVal       *json_get(const JVal *obj, const char *key);
JVal       *json_at(const JVal *arr, size_t i);
const char *json_str(const JVal *v, const char *fallback);
double      json_num(const JVal *v, double fallback);
size_t      json_len(const JVal *v);
const char *json_gets(const JVal *obj, const char *key, const char *fallback);
double      json_getn(const JVal *obj, const char *key, double fallback);

#endif
