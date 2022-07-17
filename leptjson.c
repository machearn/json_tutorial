#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <errno.h>
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

#if 0
static void* lept_context_push(lept_context* c, const lept_value* v, size_t size) {
    printf("my own verison, less efficient since push value one byte by one byte");
    assert(size > 0);
    size_t stack_base = c->top;
    const char* contents = (char*)v;
    for (int i = 0; i < size; i++)
        push_byte(c, *(contents+i));
    void* ret = c->stack+stack_base;
    c->top += size;
    return ret;
}
#endif

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top+size >= c->size) {
        while (c->top+size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char*) realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
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
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while(ISDIGIT(*p)) p++;
    }

    errno = 0;
    v->u.n = strtod(c->json, &end);
    if (errno == ERANGE && fabs(v->u.n) == HUGE_VAL) return LEPT_PARSE_NUMBER_TOO_BIG;
    if (c->json == end) return LEPT_PARSE_INVALID_VALUE;

    c->json = end;
    v->type = LEPT_NUMBER;

    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned int* u) {
    int base[4] = {4096, 256, 16, 1};
    char ch;
    int i;
    for (i = 0; i < 4; i++) {
        ch = *(p+i);
        if (ch >= '0' && ch <= '9')
            *u += (ch-'0') * base[i];
        else if ((ch >= 'a' && ch <= 'f'))
            *u += (ch-'a'+10) * base[i];
        else if ((ch >= 'A' && ch <= 'F'))
            *u += (ch-'A'+10) * base[i];
        else
            return NULL;
    }
    return p+4;
}

static void lept_encode_utf8(lept_context* c, const unsigned int u) {
    assert(u >= 0x0000 && u <= 0x10ffff);
    if (u >= 0x0000 && u <= 0x007f) {
        push_byte(c, (char)u);
    }
    else if (u >= 0x0080 && u <= 0x07ff) {
        push_byte(c, (char)(0xc0 | ((u >> 6) & 0x1f)));
        push_byte(c, (char)(0x80 | (u & 0x3f)));
    }
    else if (u >= 0x0800 && u <= 0xffff) {
        push_byte(c, (char)(0xe0 | ((u >> 12) & 0x0f)));
        push_byte(c, (char)(0x80 | ((u >> 6) & 0x3f)));
        push_byte(c, (char)(0x80 | (u & 0x3f)));
    }
    else {
        push_byte(c, (char)(0xf0 | ((u >> 18) & 0x07)));
        push_byte(c, (char)(0x80 | ((u >> 12) & 0x3f)));
        push_byte(c, (char)(0x80 | ((u >> 6) & 0x3f)));
        push_byte(c, (char)(0x80 | (u & 0x3f)));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    const char* p;
    unsigned int u;

    EXPECT(c, '\"');
    p = c->json;

    while(1) {
        char ch = *p++;
        switch(ch) {
            case '\"':
                *len = c->top - head;
                *str = (char*) lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
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
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u))) {
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        if (u >= 0xd800 && u <= 0xdbff) {
                            unsigned short low;
                            unsigned short high;

                            if (*p != '\\' || *(p+1) != 'u') {
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            else {
                                p += 2;
                                high = (unsigned short)u;
                                u = 0;
                                if (!(p = lept_parse_hex4(p, &u))) {
                                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                                }
                                low = (unsigned short)u;
                                if (low < 0xdc00 || low > 0xdfff) {
                                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                                }
                                u = 0x10000 + (high-0xd800) * 0x400 + (low-0xdc00);
                            }
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            default:
                if ((unsigned char)ch < 0x20) {
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                push_byte(c, ch);
        }
    }
}

static int lept_parse_string(lept_value* v, lept_context* c) {
    int ret;
    char* str;
    size_t len;
    if ((ret=lept_parse_string_raw(c, &str, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, str, len);
    return ret;
}

static int lept_parse_value(lept_value* v, lept_context* c);

static int lept_parse_array(lept_value* v, lept_context* c) {
    size_t size = 0;
    size_t i;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }

    while (1) {
        lept_value elem;
        lept_init(&elem);
        if ((ret=lept_parse_value(&elem, c)) != LEPT_PARSE_OK) break;
        memcpy(lept_context_push(c, sizeof(lept_value)), &elem, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            v->u.a.e = malloc(size);
            memcpy(v->u.a.e, lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }

    for (i = 0; i < size; i++)
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    return ret;
}

static int lept_parse_object(lept_value* v, lept_context* c) {
    size_t size;
    size_t i;
    lept_member m;
    int ret;
    char* str;

    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.size = 0;
        v->u.o.m = 0;
        return LEPT_PARSE_OK;
    }

    m.k = NULL;
    size = 0;

    while (1) {
        lept_init(&m.v);
        if (*c->json != '\"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }

        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK)
            break;
        memcpy((m.k = malloc(m.klen+1)), str, m.klen);
        m.k[m.klen] = '\0';

        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }

        c->json++;
        lept_parse_whitespace(c);
        if ((ret=lept_parse_value(&m.v, c)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        lept_parse_whitespace(c);
        m.k = NULL;
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == '}') {
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = size;
            size *= sizeof(lept_member);
            v->u.o.m = malloc(size);
            memcpy(v->u.o.m, lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }

    for (i = 0; i < size; i++) {
        lept_member* pop = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(pop->k);
        pop->klen = 0;
        lept_free(&pop->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_value* v, lept_context* c) {
    switch(*c->json) {
        case 'n': return lept_parse_null(v, c);
        case 't': return lept_parse_true(v, c);
        case 'f': return lept_parse_false(v, c);
        case '\"': return lept_parse_string(v, c);
        case '[': return lept_parse_array(v, c);
        case '{': return lept_parse_object(v, c);
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
    assert(c.top == 0);
    free(c.stack);

    return parse_result;
}

void lept_free(lept_value* v) {
    size_t i;
    assert(v != NULL);
    if (v->type == LEPT_STRING) {
        free(v->u.s.s);
        v->u.s.len = 0;
    }
    if (v->type == LEPT_ARRAY) {
        for (i = 0; i < v->u.a.size; i++) {
            lept_free(&v->u.a.e[i]);
        }
        free(v->u.a.e);
        v->u.a.size = 0;
    }
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

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < lept_get_array_size(v));
    return v->u.a.e+index;
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < lept_get_object_size(v));
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < lept_get_object_size(v));
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < lept_get_object_size(v));
    return &v->u.o.m[index].v;
}
