#ifndef STRACE_BTF_ATTR_H
#define STRACE_BTF_ATTR_H

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

typedef struct refcount_struct refcount_t;

#endif /* !STRACE_BTF_ATTR_H */