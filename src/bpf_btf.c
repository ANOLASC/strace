#include "bpf_btf.h"

#include <sys/syscall.h>
#include <unistd.h>
#include <byteswap.h>

#define BTF_MAX_NR_TYPES 0x7fffffffU
#define BTF_MAX_STR_OFFSET 0x7fffffffU

static inline uint64_t ptr_to_u64(const void *ptr)
{
	return (uint64_t) (unsigned long) ptr;
}

static inline int bpf_err_errno(int ret)
{
	return ret < 0 ? errno : ret;
}

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_obj_get_info_by_fd(int fd, void *info, uint32_t *info_len)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	
	attr.info.bpf_fd = fd;
	attr.info.info_len = *info_len;
	attr.info.info = ptr_to_u64(info);
	err = bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	if (!err)
		*info_len = attr.info.info_len;
	return bpf_err_errno(err);
}

int bpf_btf_get_fd_by_id(uint32_t id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.btf_id = id;

	return bpf(BPF_BTF_GET_FD_BY_ID, &attr, sizeof(attr));
}

static const char* __btf_kind_str(uint16_t kind)
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

static inline uint16_t btf_kind(const struct btf_type* btf_t)
{
	return BTF_INFO_KIND(btf_t->info);
}

const char* btf_kind_str(const struct btf_type* btf_t)
{
	return __btf_kind_str(btf_kind(btf_t));
}

static struct btf_type* btf_type_by_id(const struct btf* btf, uint32_t type_id)
{
	if (type_id == 0)
		return NULL;
	if (type_id < (uint32_t)btf->start_id)
		return btf_type_by_id(btf->base_btf, type_id);
	return btf->types_data + btf->type_offs[type_id - btf->start_id];
}

const struct btf_type* get_btf_type_by_id(const struct btf* btf, uint32_t type_id)
{
	if (type_id >= (uint32_t)btf->start_id + btf->nr_types)
		return errno = EINVAL, NULL;
	return btf_type_by_id((struct btf*)btf, type_id);
}

static void btf_bswap_hdr(struct btf_header *h)
{
	h->magic = bswap_16(h->magic);
	h->hdr_len = bswap_32(h->hdr_len);
	h->type_off = bswap_32(h->type_off);
	h->type_len = bswap_32(h->type_len);
	h->str_off = bswap_32(h->str_off);
	h->str_len = bswap_32(h->str_len);
}

static uint32_t btf__type_cnt(const struct btf *btf)
{
	return btf->start_id + btf->nr_types;
}

static int btf_parse_hdr(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	uint32_t meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		error_msg("BTF header not found\n");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			error_msg("Can't load BTF with non-native endianness due to unsupported header length %u\n",
				bswap_32(hdr->hdr_len));
			return -ENOTSUP;
		}
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		error_msg("Invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		error_msg("BTF header len %u larger than data size %u\n",
			 hdr->hdr_len, btf->raw_size);
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		error_msg("Invalid BTF total size: %u\n", btf->raw_size);
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		error_msg("Invalid BTF data sections layout: type data at %u + %u, strings data at %u + %u\n",
			 hdr->type_off, hdr->type_len, hdr->str_off, hdr->str_len);
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		error_msg("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	return 0;
}

static int btf_parse_str_sec(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	const char *start = btf->strs_data;
	const char *end = start + btf->hdr->str_len;

	if (btf->base_btf && hdr->str_len == 0)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_STR_OFFSET || end[-1]) {
		error_msg("Invalid BTF string section\n");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		error_msg("Invalid BTF string section\n");
		return -EINVAL;
	}
	return 0;
}

static bool btf_is_modifiable(const struct btf *btf)
{
	return (void *)btf->hdr != btf->raw_data;
}

#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

#define hashmap__for_each_entry_safe(map, cur, tmp, bkt)		    \
	for (bkt = 0; bkt < map->cap; bkt++)				    \
		for (cur = map->buckets[bkt];				    \
		     cur && ({tmp = cur->next; true; });		    \
		     cur = tmp)

static inline void * ERR_PTR(long error_)
{
	return (void *) error_;
}

static void hashmap__clear(struct hashmap *map)
{
	struct hashmap_entry *cur, *tmp;
	size_t bkt;

	hashmap__for_each_entry_safe(map, cur, tmp, bkt) {
		free(cur);
	}
	free(map->buckets);
	map->buckets = NULL;
	map->cap = map->cap_bits = map->sz = 0;
}

static void hashmap__free(struct hashmap *map)
{
	if (IS_ERR_OR_NULL(map))
		return;

	hashmap__clear(map);
	free(map);
}

static void strset__free(struct strset *set)
{
	if (IS_ERR_OR_NULL(set))
		return;

	hashmap__free(set->strs_hash);
	free(set->strs_data);
	free(set);
}

static void btf__free(struct btf *btf)
{
	if (IS_ERR_OR_NULL(btf))
		return;

	if (btf->fd >= 0)
		close(btf->fd);

	if (btf_is_modifiable(btf)) {
		free(btf->hdr);
		free(btf->types_data);
		strset__free(btf->strs_set);
	}
	free(btf->raw_data);
	free(btf->raw_data_swapped);
	free(btf->type_offs);
	free(btf);
}

static void btf_bswap_type_base(struct btf_type *t)
{
	t->name_off = bswap_32(t->name_off);
	t->info = bswap_32(t->info);
	t->type = bswap_32(t->type);
}

static inline uint16_t btf_vlen(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

#ifndef BTF_KIND_FUNC
#define BTF_KIND_FUNC		12	/* Function	*/
#define BTF_KIND_FUNC_PROTO	13	/* Function Proto	*/
#endif
#ifndef BTF_KIND_VAR
#define BTF_KIND_VAR		14	/* Variable	*/
#define BTF_KIND_DATASEC	15	/* Section	*/
#endif
#ifndef BTF_KIND_FLOAT
#define BTF_KIND_FLOAT		16	/* Floating point	*/
#endif
/* The kernel header switched to enums, so the following were never #defined */
#define BTF_KIND_DECL_TAG	17	/* Decl Tag */
#define BTF_KIND_TYPE_TAG	18	/* Type Tag */
#define BTF_KIND_ENUM64		19	/* Enum for up-to 64bit values */

struct btf_decl_tag {
    int32_t   component_idx;
};

/* BTF_KIND_ENUM64 is followed by multiple "struct btf_enum64".
 * The exact number of btf_enum64 is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_enum64 {
	uint32_t	name_off;
	uint32_t	val_lo32;
	uint32_t	val_hi32;
};
static inline struct btf_decl_tag *btf_decl_tag(const struct btf_type *t)
{
	return (struct btf_decl_tag *)(t + 1);
}

static int btf_type_size(const struct btf_type *t)
{
	const int base_size = sizeof(struct btf_type);
	uint16_t vlen = btf_vlen(t);

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(uint32_t);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ENUM64:
		return base_size + vlen * sizeof(struct btf_enum64);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	case BTF_KIND_VAR:
		return base_size + sizeof(struct btf_var);
	case BTF_KIND_DATASEC:
		return base_size + vlen * sizeof(struct btf_var_secinfo);
	case BTF_KIND_DECL_TAG:
		return base_size + sizeof(struct btf_decl_tag);
	default:
		error_msg("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static inline struct btf_enum *btf_enum(const struct btf_type *t)
{
	return (struct btf_enum *)(t + 1);
}

static inline struct btf_enum64 *btf_enum64(const struct btf_type *t)
{
	return (struct btf_enum64 *)(t + 1);
}

static inline struct btf_param *btf_params(const struct btf_type *t)
{
	return (struct btf_param *)(t + 1);
}

static inline struct btf_var_secinfo *
btf_var_secinfos(const struct btf_type *t)
{
	return (struct btf_var_secinfo *)(t + 1);
}

static inline struct btf_array *btf_array(const struct btf_type *t)
{
	return (struct btf_array *)(t + 1);
}

static inline void *bpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
	return realloc(ptr, total);
}

static void *bpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt)
{
	size_t new_cnt;
	void *new_data;

	if (cur_cnt + add_cnt <= *cap_cnt)
		return *data + cur_cnt * elem_sz;

	/* requested more than the set limit */
	if (cur_cnt + add_cnt > max_cnt)
		return NULL;

	new_cnt = *cap_cnt;
	new_cnt += new_cnt / 4;		  /* expand by 25% */
	if (new_cnt < 16)		  /* but at least 16 elements */
		new_cnt = 16;
	if (new_cnt > max_cnt)		  /* but not exceeding a set limit */
		new_cnt = max_cnt;
	if (new_cnt < cur_cnt + add_cnt)  /* also ensure we have enough memory */
		new_cnt = cur_cnt + add_cnt;

	new_data = bpf_reallocarray(*data, new_cnt, elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

static void *btf_add_type_offs_mem(struct btf *btf, size_t add_cnt)
{
	return bpf_add_mem((void **)&btf->type_offs, &btf->type_offs_cap, sizeof(uint32_t),
			      btf->nr_types, BTF_MAX_NR_TYPES, add_cnt);
}

static int btf_add_type_idx_entry(struct btf *btf, uint32_t type_off)
{
	uint32_t *p;

	p = btf_add_type_offs_mem(btf, 1);
	if (!p)
		return -ENOMEM;

	*p = type_off;
	return 0;
}

static inline struct btf_member *btf_members(const struct btf_type *t)
{
	return (struct btf_member *)(t + 1);
}

static inline struct btf_var *btf_var(const struct btf_type *t)
{
	return (struct btf_var *)(t + 1);
}

static int btf_bswap_type_rest(struct btf_type *t)
{
	struct btf_var_secinfo *v;
	struct btf_enum64 *e64;
	struct btf_member *m;
	struct btf_array *a;
	struct btf_param *p;
	struct btf_enum *e;
	uint16_t vlen = btf_vlen(t);
	int i;

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return 0;
	case BTF_KIND_INT:
		*(uint32_t *)(t + 1) = bswap_32(*(uint32_t *)(t + 1));
		return 0;
	case BTF_KIND_ENUM:
		for (i = 0, e = btf_enum(t); i < vlen; i++, e++) {
			e->name_off = bswap_32(e->name_off);
			e->val = bswap_32(e->val);
		}
		return 0;
	case BTF_KIND_ENUM64:
		for (i = 0, e64 = btf_enum64(t); i < vlen; i++, e64++) {
			e64->name_off = bswap_32(e64->name_off);
			e64->val_lo32 = bswap_32(e64->val_lo32);
			e64->val_hi32 = bswap_32(e64->val_hi32);
		}
		return 0;
	case BTF_KIND_ARRAY:
		a = btf_array(t);
		a->type = bswap_32(a->type);
		a->index_type = bswap_32(a->index_type);
		a->nelems = bswap_32(a->nelems);
		return 0;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		for (i = 0, m = btf_members(t); i < vlen; i++, m++) {
			m->name_off = bswap_32(m->name_off);
			m->type = bswap_32(m->type);
			m->offset = bswap_32(m->offset);
		}
		return 0;
	case BTF_KIND_FUNC_PROTO:
		for (i = 0, p = btf_params(t); i < vlen; i++, p++) {
			p->name_off = bswap_32(p->name_off);
			p->type = bswap_32(p->type);
		}
		return 0;
	case BTF_KIND_VAR:
		btf_var(t)->linkage = bswap_32(btf_var(t)->linkage);
		return 0;
	case BTF_KIND_DATASEC:
		for (i = 0, v = btf_var_secinfos(t); i < vlen; i++, v++) {
			v->type = bswap_32(v->type);
			v->offset = bswap_32(v->offset);
			v->size = bswap_32(v->size);
		}
		return 0;
	case BTF_KIND_DECL_TAG:
		btf_decl_tag(t)->component_idx = bswap_32(btf_decl_tag(t)->component_idx);
		return 0;
	default:
		error_msg("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static int btf_parse_type_sec(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	void *next_type = btf->types_data;
	void *end_type = next_type + hdr->type_len;
	int err, type_size;

	while (next_type + sizeof(struct btf_type) <= end_type) {
		if (btf->swapped_endian)
			btf_bswap_type_base(next_type);

		type_size = btf_type_size(next_type);
		if (type_size < 0)
			return type_size;
		if (next_type + type_size > end_type) {
			error_msg("BTF type [%d] is malformed\n", btf->start_id + btf->nr_types);
			return -EINVAL;
		}

		if (btf->swapped_endian && btf_bswap_type_rest(next_type))
			return -EINVAL;

		err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
		if (err)
			return err;

		next_type += type_size;
		btf->nr_types++;
	}

	if (next_type != end_type) {
		error_msg("BTF types data is malformed\n");
		return -EINVAL;
	}

	return 0;
}

static struct btf *btf_new(const void *data, uint32_t size, struct btf *base_btf)
{
	struct btf *btf;
	int err;

	btf = calloc(1, sizeof(struct btf));
	if (!btf)
		return NULL;

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	btf->raw_data = malloc(size);
	if (!btf->raw_data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf->raw_data, data, size);
	btf->raw_size = size;

	btf->hdr = btf->raw_data;
	err = btf_parse_hdr(btf);
	if (err)
		goto done;

	btf->strs_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->str_off;
	btf->types_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->type_off;

	err = btf_parse_str_sec(btf);
	err = err ?: btf_parse_type_sec(btf);
	if (err)
		goto done;

done:
	if (err) {
		btf__free(btf);
		return ERR_PTR(err);
	}

	return btf;
}

struct btf* fetch_btf_from_fd(int btf_fd, struct btf *base_btf)
{
	struct bpf_btf_info btf_info;
	uint32_t len = sizeof(btf_info);
	uint32_t last_size;
	struct btf *btf;
	void *ptr;
	int err;

	last_size = 4096;
	ptr = malloc(last_size);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	memset(&btf_info, 0, sizeof(btf_info));
	btf_info.btf = ptr_to_u64(ptr);
	btf_info.btf_size = last_size;
	err = bpf_obj_get_info_by_fd(btf_fd, &btf_info, &len);

	if (!err && btf_info.btf_size > last_size) {
		void *temp_ptr;

		last_size = btf_info.btf_size;
		temp_ptr = realloc(ptr, last_size);
		if (!temp_ptr) {
			btf = ERR_PTR(-ENOMEM);
			goto exit_free;
		}
		ptr = temp_ptr;

		len = sizeof(btf_info);
		memset(&btf_info, 0, sizeof(btf_info));
		btf_info.btf = ptr_to_u64(ptr);
		btf_info.btf_size = last_size;

		err = bpf_obj_get_info_by_fd(btf_fd, &btf_info, &len);
	}

	if (err || btf_info.btf_size > last_size) {
		btf = err ? ERR_PTR(-errno) : ERR_PTR(-E2BIG);
		goto exit_free;
	}

	btf = btf_new(ptr, btf_info.btf_size, base_btf);

exit_free:
	free(ptr);
	return btf;
}

int open_pidfd_and_get_fd(int pid, int fd)
{
	int ret = syscall(SYS_pidfd_open, pid, 0);
	if (ret == -1) {
		int err = -errno;
		error_msg("%s\n", strerror(ret));
		return err;
	}

	int pidfd = ret;

	int ret1 = syscall(438, pidfd, fd, 0);
	if (ret1 == -1) {
		int err = -errno;
		error_msg("%s\n", strerror(ret1));
		return err;
	}

	close(pidfd);

	return ret1;
}

void print_map_btf(struct tcb * const tcp, int map_fd)
{
	int tracee_map_fds = open_pidfd_and_get_fd(tcp->pid, map_fd);
	struct bpf_map_info info = {};
	uint32_t len = sizeof(info);
	bpf_obj_get_info_by_fd(tracee_map_fds, &info, &len);
	close(tracee_map_fds);

	tprint_struct_begin();
	PRINT_FIELD_STRING(info, name, strlen(info.name), 0);
	tprint_struct_next();
	PRINT_FIELD_U(info, type);
	tprint_struct_next();
	PRINT_FIELD_U(info, id);
	tprint_struct_next();
	PRINT_FIELD_U(info, key_size);
	tprint_struct_next();
	PRINT_FIELD_U(info, value_size);
	tprint_struct_next();
	PRINT_FIELD_U(info, max_entries);
	tprint_struct_next();
	PRINT_FIELD_U(info, btf_id);
	tprint_struct_next();

	uint32_t btf_fd = bpf_btf_get_fd_by_id(info.btf_id);
	struct bpf_btf_info btf_info = {};
	uint32_t btf_len = sizeof(btf_info);
	bpf_obj_get_info_by_fd(btf_fd, &btf_info, &btf_len);
	struct btf* btf = fetch_btf_from_fd(btf_fd, NULL);
	close(btf_fd);

	PRINT_FIELD_U(info, btf_key_type_id);
	const struct btf_type* btf_key_type = get_btf_type_by_id(btf, info.btf_key_type_id);
	if (btf_key_type)
		tprintf(", btf_kind=%s", btf_kind_str(btf_key_type));
	tprint_struct_next();
	PRINT_FIELD_U(info, btf_value_type_id);
	const struct btf_type* btf_value_type = get_btf_type_by_id(btf, info.btf_value_type_id);
	if (btf_value_type)
		tprintf(", btf_kind=%s", btf_kind_str(btf_value_type));

	tprint_struct_end();
}