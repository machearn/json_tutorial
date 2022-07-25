#ifndef LEPT_JSON_H_
#define LEPT_JSON_H_

#include <stddef.h>

#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define ISWHITESPACE(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\r' || (ch) == '\n' || (ch) == '\0')

typedef enum {
LEPT_NULL,
LEPT_FALSE,
LEPT_TRUE,
LEPT_NUMBER,
LEPT_STRING,
LEPT_ARRAY,
LEPT_OBJECT
}lept_type;

typedef struct lept_value lept_value;
typedef struct lept_member lept_member;

struct lept_value {
    union{
        struct {char* s; size_t len;}s;
        struct {lept_member* m; size_t size;}o;
        struct {lept_value* e; size_t size; size_t capacity;}a;
        double n;
    }u;
    lept_type type;
};

struct lept_member {
    char* k;
    size_t klen;
    lept_value v;
};

int lept_parse(lept_value* v, const char* json);
char* lept_stringfy(const lept_value* v, size_t* len);

enum {
LEPT_PARSE_OK = 0,
LEPT_PARSE_EXPECT_VALUE,
LEPT_PARSE_INVALID_VALUE,
LEPT_PARSE_ROOT_NOT_SINGULAR,
LEPT_PARSE_NUMBER_TOO_BIG,
LEPT_PARSE_MISS_QUOTATION_MARK,
LEPT_PARSE_INVALID_STRING_ESCAPE,
LEPT_PARSE_INVALID_STRING_CHAR,
LEPT_PARSE_INVALID_UNICODE_HEX,
LEPT_PARSE_INVALID_UNICODE_SURROGATE,
LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
LEPT_PARSE_MISS_KEY,
LEPT_PARSE_MISS_COLON,
LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};


#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0)

void lept_copy(lept_value* dst, const lept_value* src);
void lept_move(lept_value* dst, lept_value* src);
void lept_swap(lept_value* lhs, lept_value* rhs);

void lept_free(lept_value* v);
#define lept_set_null(v) lept_free(v)

lept_type lept_get_type(const lept_value* v);
int lept_is_equal(const lept_value* lhs, const lept_value* rhs);

int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

void lept_set_array(lept_value* v, size_t capacity);
size_t lept_get_array_size(const lept_value* v);
size_t lept_get_array_capacity(const lept_value* v);
void lept_reserve_array(lept_value* v, size_t capacity);
void lept_shrink_array(lept_value* v);
void lept_clear_array(lept_value* v);
lept_value* lept_get_array_element(const lept_value* v, size_t index);
lept_value* lept_pushback_array_element(lept_value* v);
void lept_popback_array_element(lept_value* v);
lept_value* lept_insert_array_element(lept_value* v, size_t index);
void lept_erase_array_element(lept_value* v, size_t index, size_t count);

size_t lept_get_object_size(const lept_value* v);
const char* lept_get_object_key(const lept_value* v, size_t index);
size_t lept_get_object_key_length(const lept_value* v, size_t index);
lept_value* lept_get_object_value(const lept_value* v, size_t index);

#endif
