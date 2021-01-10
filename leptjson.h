#ifndef LEPT_JSON_H_
#define LEPT_JSON_H_

typedef enum {
LEPT_NULL,
LEPT_FALSE,
LEPT_TRUE,
LEPT_NUMBER,
LEPT_STRING,
LEPT_ARRAY,
LEPT_OBJECT
}lept_type;

typedef struct {
    lept_type type;
}lept_value;

int lept_parse(lept_type* v, const char* json);

enum {
LEPT_PARSE_OK = 0,
LEPT_PARSE_EXPECT_VALUE,
LEPT_PARSE_INVALID_VALUE,
LEPT_PARSE_ROOT_NOT_SINGULAR
};

lept_type lept_get_value(const lept_value* value);

#endif
