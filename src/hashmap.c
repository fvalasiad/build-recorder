
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<error.h>
#include	<errno.h>
#include	<pthread.h>
#include	"hashmap.h"

#define DEFAULT_CAPACITY 1024

struct bucket {
    key_type *keys;
    value_type *values;
    int size;
    int capacity;

    pthread_mutex_t lock;
};

int
hash_str(char *str)
{
    int hash = 7;

    while (*str) {
	hash = hash * 31 + *str;
	++str;
    }

    return hash;
}

static void
bucket_reallocate(bucket *self);

static void
bucket_new(bucket *self, int capacity)
{
    self->capacity = capacity;
    self->size = 0;

    self->keys = calloc(capacity, sizeof(key_type));
    if(!self->keys) {
	error(EXIT_FAILURE, errno, "on bucket_new keys calloc");
    }

    self->values = calloc(capacity, sizeof(value_type));
    if(!self->values) {
	error(EXIT_FAILURE, errno, "on bucket_new values calloc");
    }

    pthread_mutex_init(&self->lock, NULL);
}

static char
bucket_insert(bucket *self, key_type key, value_type *value, value_type **dest)
{
    if(self->size == self->capacity) {
	bucket_reallocate(self);
    }

    int pos = hash_str(key) & (self->capacity - 1);

    while(pos != self->capacity && self->keys[pos] && strcmp(self->keys[pos], key)) {
	++pos;
    }

    if(pos == self->capacity) {
	pos = 0;
	while (self->keys[pos] && strcmp(self->keys[pos], key)) {
	    ++pos;
	}
    }

    char ret = 0;
    if(!self->keys[pos]) {
	self->keys[pos] = key;
	self->values[pos] = *value;
	++self->size;
	ret = 1;
    }

    *dest = self->values + pos;

    return ret;
}

static void
bucket_free(bucket *self)
{
    free(self->keys);
    free(self->values);
}

static void
bucket_reallocate(bucket *self)
{
    bucket b;

    bucket_new(&b, self->capacity * 2);

    for (int i = 0; i < self->capacity; ++i) {
	if (!self->keys[i])
	    continue;

	value_type *dest;
	bucket_insert(&b, self->keys[i], self->values + i, &dest);
    }

    bucket_free(self);
    *self = b;
}

static void
hashmap_reallocate(hashmap *self);

void
hashmap_new(hashmap *self)
{
    self->buckets = malloc(DEFAULT_CAPACITY * sizeof(bucket));

    if (!self->buckets) 
	error(EXIT_FAILURE, errno, "on hashmap_new malloc");

    for(int i = 0; i < DEFAULT_CAPACITY; ++i) {
	bucket_new(self->buckets + i, 32);
    }
}

static int fcount = 0;
static pthread_mutex_t lock;

char 
hashmap_insert(hashmap *self, key_type key, value_type *value, value_type *dest)
{
    bucket *b = self->buckets + (hash_str(key) & (DEFAULT_CAPACITY - 1));
    pthread_mutex_lock(&b->lock);

    value_type *ptr;
    char ret = bucket_insert(b, key, value, &ptr);
    if(ret) {
	sprintf(ptr->outname, ":f%d", fcount++);
    }

    *dest = *ptr;
    
    pthread_mutex_unlock(&b->lock);

    return ret;
}
