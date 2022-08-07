#ifndef STRACE_BTF_ATTR_H
#define STRACE_BTF_ATTR_H

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

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

enum BTF_KIND {
	BTF_KIND_UNKN = 0,	/* Unknown	*/
	BTF_KIND_INT = 1,	/* Integer	*/
	BTF_KIND_PTR = 2,	/* Pointer	*/
	BTF_KIND_ARRAY = 3,	/* Array	*/
	BTF_KIND_STRUCT = 4,	/* Struct	*/
	BTF_KIND_UNION = 5,	/* Union	*/
	BTF_KIND_ENUM = 6,	/* Enumeration up to 32-bit values */
	BTF_KIND_FWD = 7,	/* Forward	*/
	BTF_KIND_TYPEDEF = 8,	/* Typedef	*/
	BTF_KIND_VOLATILE = 9,	/* Volatile	*/
	BTF_KIND_CONST = 10,	/* Const	*/
	BTF_KIND_RESTRICT = 11,	/* Restrict	*/
	BTF_KIND_FUNC = 12,	/* Function	*/
	BTF_KIND_FUNC_PROTO = 13,	/* Function Proto	*/
	BTF_KIND_VAR = 14,	/* Variable	*/
	BTF_KIND_DATASEC = 15,	/* Section	*/
	BTF_KIND_FLOAT = 16,	/* Floating point	*/
	BTF_KIND_DECL_TAG = 17,	/* Decl Tag */
	BTF_KIND_TYPE_TAG = 18,	/* Type Tag */
	BTF_KIND_ENUM64 = 19,	/* Enumeration up to 64-bit values */

	NR_BTF_KINDS,
	BTF_KIND_MAX = NR_BTF_KINDS - 1,
};

struct strset {
	void* strs_data;
	size_t strs_data_len;
	size_t strs_data_cap;
	size_t strs_data_max_len;
	struct hashmap* strs_hash;
};

struct btf_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32	type_off;	/* offset of type section	*/
	__u32	type_len;	/* length of type section	*/
	__u32	str_off;	/* offset of string section	*/
	__u32	str_len;	/* length of string section	*/
};

struct btf {
	void* raw_data;
	void* raw_data_swapped;
	__u32 raw_size;
	bool swapped_endian;
	struct btf_header* hdr;
	void* types_data;
	size_t types_data_cap;
	__u32* type_offs;
	size_t type_offs_cap;
	__u32 nr_types;
	struct btf* base_btf;
	int start_id;
	int start_str_off;
	void* strs_data;
	struct strset* strs_set;
	bool strs_deduped;
	int fd;
	int ptr_sz;
};

#define BTF_INFO_KIND(info)	(((info) >> 24) & 0x1f)

static const char* __btf_kind_str(__u16 kind)
{
	switch (kind) {
	case BTF_KIND_UNKN: return "void";
	case BTF_KIND_INT: return "int";
	case BTF_KIND_PTR: return "ptr";
	case BTF_KIND_ARRAY: return "array";
	case BTF_KIND_STRUCT: return "struct";
	case BTF_KIND_UNION: return "union";
	case BTF_KIND_ENUM: return "enum";
	case BTF_KIND_FWD: return "fwd";
	case BTF_KIND_TYPEDEF: return "typedef";
	case BTF_KIND_VOLATILE: return "volatile";
	case BTF_KIND_CONST: return "const";
	case BTF_KIND_RESTRICT: return "restrict";
	case BTF_KIND_FUNC: return "func";
	case BTF_KIND_FUNC_PROTO: return "func_proto";
	case BTF_KIND_VAR: return "var";
	case BTF_KIND_DATASEC: return "datasec";
	case BTF_KIND_FLOAT: return "float";
	case BTF_KIND_DECL_TAG: return "decl_tag";
	case BTF_KIND_TYPE_TAG: return "type_tag";
	case BTF_KIND_ENUM64: return "enum64";
	default: return "unknown";
	}
}

static inline __u16 btf_kind(const struct btf_type* t)
{
	return BTF_INFO_KIND(t->info);
}

const char* btf_kind_str(const struct btf_type* t)
{
	return __btf_kind_str(btf_kind(t));
}

struct btf_type* btf_type_by_id(const struct btf* btf, __u32 type_id)
{
	if (type_id == 0)
		return NULL;
	if (type_id < btf->start_id)
		return btf_type_by_id(btf->base_btf, type_id);
	return btf->types_data + btf->type_offs[type_id - btf->start_id];
}

const struct btf_type* btf__type_by_id(const struct btf* btf, __u32 type_id)
{
	if (type_id >= btf->start_id + btf->nr_types)
		return errno = EINVAL, NULL;
	return btf_type_by_id((struct btf*)btf, type_id);
}

void print_btf_kind_str(const uint32_t type_id)
{
	printf("%s", btf_kind_str(btf_kind(btf__type_by_id(NULL, type_id))));
}

#endif /* !STRACE_BTF_ATTR_H */