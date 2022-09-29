#ifndef STRACE_BPF_BTF_H
# define STRACE_BPF_BTF_H

#include "defs.h"

#ifdef HAVE_LINUX_BPF_H
# include <linux/bpf.h>
# include <linux/btf.h>
#endif

#ifndef BTF_KIND_FLOAT
#define BTF_KIND_FLOAT 16	/* Floating point	*/
#endif

#ifndef BTF_KIND_DECL_TAG
#define BTF_KIND_DECL_TAG 17	/* Decl Tag */
#endif

#ifndef BTF_KIND_TYPE_TAG
#define BTF_KIND_TYPE_TAG 18	/* Type Tag */
#endif

#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19	/* Enumeration up to 64-bit values */
#endif

extern int open_pidfd_and_get_fd(int pid, int fd);
extern int bpf_obj_get_info_by_fd(int fd, void *info, uint32_t *info_len);
extern int bpf_btf_get_fd_by_id(uint32_t id);
extern struct btf* fetch_btf_from_fd(int btf_fd, struct btf *base_btf);
extern const struct btf_type* get_btf_type_by_id(const struct btf* btf, uint32_t type_id);
// extern const char *btf_str(const struct btf *btf, uint32_t off);
extern const char* btf_kind_str(const struct btf_type* btf_t);
extern void print_map_btf(struct tcb * const tcp, int map_fd);

struct strset {
	void* strs_data;
	size_t strs_data_len;
	size_t strs_data_cap;
	size_t strs_data_max_len;
	struct hashmap* strs_hash;
};

struct btf {
	void* raw_data;
	void* raw_data_swapped;
	uint32_t raw_size;
	bool swapped_endian;
	struct btf_header* hdr;
	void* types_data;
	size_t types_data_cap;
	uint32_t* type_offs;
	size_t type_offs_cap;
	uint32_t nr_types;
	struct btf* base_btf;
	int start_id;
	int start_str_off;
	void* strs_data;
	struct strset* strs_set;
	bool strs_deduped;
	int fd;
	int ptr_sz;
};

typedef size_t(*hashmap_hash_fn)(const void* key, void* ctx);
typedef bool (*hashmap_equal_fn)(const void* key1, const void* key2, void* ctx);

struct hashmap_entry {
	const void* key;
	void* value;
	struct hashmap_entry* next;
};

struct hashmap {
	hashmap_hash_fn hash_fn;
	hashmap_equal_fn equal_fn;
	void* ctx;

	struct hashmap_entry** buckets;
	size_t cap;
	size_t cap_bits;
	size_t sz;
};

#endif /* !STRACE_BPF_BTF_H */