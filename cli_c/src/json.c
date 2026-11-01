/* json.c - see json.h */
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ arena */
typedef struct Block { struct Block *next; size_t used, cap; char data[]; } Block;
struct JDoc { Block *blocks; JVal *root; };

static void *arena_alloc(JDoc *d, size_t n) {
    n = (n + 15) & ~(size_t)15;
    Block *b = d->blocks;
    if (!b || b->used + n > b->cap) {
        size_t cap = n > 65536 ? n : 65536;
        Block *nb = malloc(sizeof(Block) + cap);
        if (!nb) return NULL;
        nb->next = b;
        nb->used = 0;
        nb->cap = cap;
        d->blocks = nb;
        b = nb;
    }
    void *p = b->data + b->used;
    b->used += n;
    return p;
}

void json_free(JDoc *d) {
    if (!d) return;
    Block *b = d->blocks;
    while (b) { Block *n = b->next; free(b); b = n; }
    free(d);
}

/* ------------------------------------------------------------------ parser */
typedef struct {
    const char *s, *end;
    JDoc *doc;
    int depth;
    char *err;
    size_t errlen;
    int failed;
} P;

static void fail(P *p, const char *msg) {
    if (!p->failed && p->err) snprintf(p->err, p->errlen, "%s at byte %ld", msg, (long)(p->end - p->s));
    p->failed = 1;
}

static void ws(P *p) {
    while (p->s < p->end && (*p->s == ' ' || *p->s == '\t' || *p->s == '\n' || *p->s == '\r')) p->s++;
}

static JVal *newval(P *p, JType t) {
    JVal *v = arena_alloc(p->doc, sizeof(JVal));
    if (!v) { fail(p, "out of memory"); return NULL; }
    memset(v, 0, sizeof *v);
    v->type = t;
    return v;
}

static int hex4(const char *s, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static char *parse_string(P *p) {
    if (p->s >= p->end || *p->s != '"') { fail(p, "expected string"); return NULL; }
    p->s++;
    /* worst case output length == input length */
    const char *q = p->s;
    while (q < p->end && *q != '"') { if (*q == '\\') q++; q++; }
    if (q >= p->end) { fail(p, "unterminated string"); return NULL; }
    char *out = arena_alloc(p->doc, (size_t)(q - p->s) + 4);
    if (!out) { fail(p, "out of memory"); return NULL; }
    size_t n = 0;
    while (p->s < p->end && *p->s != '"') {
        unsigned char c = (unsigned char)*p->s++;
        if (c < 0x20) { fail(p, "control character in string"); return NULL; }
        if (c != '\\') { out[n++] = (char)c; continue; }
        if (p->s >= p->end) break;
        char e = *p->s++;
        switch (e) {
            case '"': out[n++] = '"'; break;
            case '\\': out[n++] = '\\'; break;
            case '/': out[n++] = '/'; break;
            case 'b': out[n++] = '\b'; break;
            case 'f': out[n++] = '\f'; break;
            case 'n': out[n++] = '\n'; break;
            case 'r': out[n++] = '\r'; break;
            case 't': out[n++] = '\t'; break;
            case 'u': {
                unsigned cp;
                if (p->end - p->s < 4 || hex4(p->s, &cp)) { fail(p, "bad \\u escape"); return NULL; }
                p->s += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF && p->end - p->s >= 6 && p->s[0] == '\\' && p->s[1] == 'u') {
                    unsigned lo;
                    if (!hex4(p->s + 2, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        p->s += 6;
                    }
                }
                if (cp >= 0xD800 && cp <= 0xDFFF) cp = '?';
                /* encode as UTF-8 (fits: \uXXXX is 6 input bytes, max 4 output bytes) */
                if (cp < 0x80) out[n++] = (char)cp;
                else if (cp < 0x800) { out[n++] = (char)(0xC0 | (cp >> 6)); out[n++] = (char)(0x80 | (cp & 0x3F)); }
                else if (cp < 0x10000) {
                    out[n++] = (char)(0xE0 | (cp >> 12)); out[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[n++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    out[n++] = (char)(0xF0 | (cp >> 18)); out[n++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                    out[n++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[n++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: fail(p, "bad escape"); return NULL;
        }
    }
    if (p->s >= p->end) { fail(p, "unterminated string"); return NULL; }
    p->s++;
    out[n] = 0;
    return out;
}

static JVal *parse_value(P *p);

static JVal *parse_container(P *p, int is_obj) {
    if (++p->depth > JSON_MAX_DEPTH) { fail(p, "nesting too deep"); return NULL; }
    JVal *v = newval(p, is_obj ? J_OBJ : J_ARR);
    if (!v) return NULL;
    p->s++;
    ws(p);
    char close = is_obj ? '}' : ']';
    JVal *tail = NULL;
    if (p->s < p->end && *p->s == close) { p->s++; p->depth--; return v; }
    for (;;) {
        char *key = NULL;
        ws(p);
        if (is_obj) {
            key = parse_string(p);
            if (!key) return NULL;
            ws(p);
            if (p->s >= p->end || *p->s != ':') { fail(p, "expected ':'"); return NULL; }
            p->s++;
        }
        JVal *c = parse_value(p);
        if (!c) return NULL;
        c->key = key;
        if (tail) tail->next = c; else v->child = c;
        tail = c;
        v->len++;
        ws(p);
        if (p->s < p->end && *p->s == ',') { p->s++; continue; }
        if (p->s < p->end && *p->s == close) { p->s++; break; }
        fail(p, is_obj ? "expected ',' or '}'" : "expected ',' or ']'");
        return NULL;
    }
    p->depth--;
    return v;
}

static JVal *parse_value(P *p) {
    ws(p);
    if (p->failed) return NULL;
    if (p->s >= p->end) { fail(p, "unexpected end"); return NULL; }
    char c = *p->s;
    if (c == '{') return parse_container(p, 1);
    if (c == '[') return parse_container(p, 0);
    if (c == '"') {
        char *s = parse_string(p);
        if (!s) return NULL;
        JVal *v = newval(p, J_STR);
        if (v) v->str = s;
        return v;
    }
    if ((size_t)(p->end - p->s) >= 4 && !strncmp(p->s, "true", 4)) {
        p->s += 4; JVal *v = newval(p, J_BOOL); if (v) v->num = 1; return v;
    }
    if ((size_t)(p->end - p->s) >= 5 && !strncmp(p->s, "false", 5)) {
        p->s += 5; return newval(p, J_BOOL);
    }
    if ((size_t)(p->end - p->s) >= 4 && !strncmp(p->s, "null", 4)) {
        p->s += 4; return newval(p, J_NULL);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char buf[64];
        size_t n = 0;
        while (p->s < p->end && n < sizeof buf - 1 && strchr("+-0123456789.eE", *p->s)) buf[n++] = *p->s++;
        buf[n] = 0;
        char *endp;
        double d = strtod(buf, &endp);
        if (endp == buf) { fail(p, "bad number"); return NULL; }
        JVal *v = newval(p, J_NUM);
        if (v) v->num = d;
        return v;
    }
    fail(p, "unexpected character");
    return NULL;
}

JDoc *json_parse(const char *text, size_t len, char *err, size_t errlen) {
    if (err && errlen) err[0] = 0;
    if (len > JSON_MAX_BYTES) {
        if (err) snprintf(err, errlen, "JSON too large");
        return NULL;
    }
    JDoc *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    P p = {text, text + len, d, 0, err, errlen, 0};
    d->root = parse_value(&p);
    ws(&p);
    if (!p.failed && p.s != p.end) fail(&p, "trailing data");
    if (p.failed || !d->root) { json_free(d); return NULL; }
    return d;
}

JDoc *json_parse_file(const char *path, char *err, size_t errlen) {
    FILE *f = fopen(path, "rb");
    if (!f) { if (err) snprintf(err, errlen, "cannot open %s", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (unsigned long)sz > JSON_MAX_BYTES) {
        fclose(f);
        if (err) snprintf(err, errlen, "JSON file too large");
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    JDoc *d = json_parse(buf, rd, err, errlen);
    free(buf);
    return d;
}

JVal *json_root(JDoc *d) { return d ? d->root : NULL; }

/* ------------------------------------------------------------------ lookups */
JVal *json_get(const JVal *o, const char *key) {
    if (!o || o->type != J_OBJ) return NULL;
    for (JVal *c = o->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key)) return c;
    return NULL;
}

JVal *json_at(const JVal *a, size_t i) {
    if (!a || (a->type != J_ARR && a->type != J_OBJ)) return NULL;
    JVal *c = a->child;
    while (c && i--) c = c->next;
    return c;
}

const char *json_str(const JVal *v, const char *fb) { return v && v->type == J_STR ? v->str : fb; }
double json_num(const JVal *v, double fb) { return v && (v->type == J_NUM || v->type == J_BOOL) ? v->num : fb; }
size_t json_len(const JVal *v) { return v && (v->type == J_ARR || v->type == J_OBJ) ? v->len : 0; }
const char *json_gets(const JVal *o, const char *k, const char *fb) { return json_str(json_get(o, k), fb); }
double json_getn(const JVal *o, const char *k, double fb) { return json_num(json_get(o, k), fb); }
