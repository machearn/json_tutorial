#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "leptjson.h"

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)

typedef struct {
    const char* json;
}lept_context;


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

    v->n = strtod(c->json, &end);
    if (fabs(v->n) == HUGE_VAL) return LEPT_PARSE_NUMBER_TOO_BIG;
    if (c->json == end) return LEPT_PARSE_INVALID_VALUE;

    c->json = end;
    v->type = LEPT_NUMBER;

    return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_value* v, lept_context*c ) {
    switch(*c->json) {
        case 'n': return lept_parse_null(v, c);
        case 't': return lept_parse_true(v, c);
        case 'f': return lept_parse_false(v, c);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default: return lept_parse_number(v, c);
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int parse_result;

    assert(v != NULL);

    c.json = json;
    v->type = LEPT_NULL;

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

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
