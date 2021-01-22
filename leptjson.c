#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include "leptjson.h"

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)

#ifndef STACK_INITIAL_SIZE
#define STACK_INITIAL_SIZE 256
#endif

typedef struct {
    const char* json;
    char* stack;
    size_t size;
    size_t top;
}lept_context;

static void init_stack(lept_context* c) {
    c->size = STACK_INITIAL_SIZE;
    c->top = 0;
    c->stack = (char*) malloc(c->size);
}

static void push_byte(lept_context* c, const char ch) {
    if (c->top+1 < c->size) {
        *(c->stack + c->top) = ch;
        c->top++;
    }
    else {
        c->size += c->size >> 1;
        c->stack = (char*) realloc(c->stack, c->size);
        *(c->stack + c->top) = ch;
        c->top++;
    }
}

static void* pop_bytes(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}


static void lept_parse_whitespace(lept_context* c) {
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_null(lept_value* v, lept_context* c) {
    EXPECT(c, 'n');
    if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
}

static int lept_parse_true(lept_value* v, lept_context* c) {
    EXPECT(c, 't');
    if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
}

static int lept_parse_false(lept_value* v, lept_context* c) {
    EXPECT(c, 'f');
    if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 4;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_value* v, lept_context* c) {
    char* end;
    const char* p = c->json;

    if (*p == '-') p++;

    if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;

    if (*p == '0') {
        p++;
        if (*p != '.' && *p != 'e' && *p != 'E' && !ISWHITESPACE(*p))
            return LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
    else {
        if (ISDIGIT1TO9(*p)) p++;
        while(ISDIGIT(*p)) p++;
    }

    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while(ISDIGIT(*p)) p++;
    }

    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '-' || *p == '+') p++;
        while(ISDIGIT(*p)) p++;
    }

    if (!ISWHITESPACE(*p)) return LEPT_PARSE_INVALID_VALUE;

    v->u.n = strtod(c->json, &end);
    if (fabs(v->u.n) == HUGE_VAL) return LEPT_PARSE_NUMBER_TOO_BIG;
    if (c->json == end) return LEPT_PARSE_INVALID_VALUE;

    c->json = end;
    v->type = LEPT_NUMBER;

    return LEPT_PARSE_OK;
}

static int lept_parse_string(lept_value* v, lept_context* c) {
    size_t head = c->top;
    size_t len;
    const char* p;

    EXPECT(c, '\"');
    p = c->json;

    while(1) {
        char ch = *p++;
        switch(ch) {
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char*) pop_bytes(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            case '\\':
                ch = *p++;
                switch(ch) {
                    case '\"':
                        push_byte(c, '\"');
                        break;
                    case '\\':
                        push_byte(c, '\\');
                        break;
                    case '/':
                        push_byte(c, '/');
                        break;
                    case 'b':
                        push_byte(c, '\b');
                        break;
                    case 'f':
                        push_byte(c, '\f');
                        break;
                    case 'n':
                        push_byte(c, '\n');
                        break;
                    case 'r':
                        push_byte(c, '\r');
                        break;
                    case 't':
                        push_byte(c, '\t');
                        break;
                    default:
                        c->top = head;
                        return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            default:
                if ((unsigned char)ch < 0x20) {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                push_byte(c, ch);
        }
    }
}

static int lept_parse_value(lept_value* v, lept_context* c) {
    switch(*c->json) {
        case 'n': return lept_parse_null(v, c);
        case 't': return lept_parse_true(v, c);
        case 'f': return lept_parse_false(v, c);
        case '\"': return lept_parse_string(v, c);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default: return lept_parse_number(v, c);
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int parse_result;

    assert(v != NULL);

    c.json = json;
    init_stack(&c);

    lept_init(v);

    lept_parse_whitespace(&c);

    parse_result = lept_parse_value(v, &c);
    if(parse_result == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if(*c.json != '\0') {
            parse_result = LEPT_PARSE_ROOT_NOT_SINGULAR;
            v->type = LEPT_NULL;
        }
    }

    return parse_result;
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING) free(v->u.s.s);
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    if (v->type == LEPT_TRUE) return 1;
    else return 0;
}

void lept_set_boolean(lept_value* v, int b) {
    assert(v != NULL);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
    assert(v != NULL);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*) malloc(len+1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}
