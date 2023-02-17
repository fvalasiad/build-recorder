
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "types.h"

/* Simple hashmap with open addressing linear probing. */

typedef char *key_type;
typedef FILE_INFO value_type;

typedef struct bucket bucket;

typedef struct {
    bucket *buckets;
} hashmap;

void hashmap_new(hashmap *self);

char hashmap_insert(hashmap *self, key_type key, value_type *value, value_type *dest);
