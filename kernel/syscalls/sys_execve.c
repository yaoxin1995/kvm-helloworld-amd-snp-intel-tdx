#include <elf/elf.h>
#include <hypercalls/hp_read.h>
#include <mm/smalloc.h>
#include <mm/kmalloc.h>
#include <mm/mmap.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_close.h>
#include <syscalls/sys_execve.h>
#include <syscalls/sys_mmap.h>
#include <syscalls/sys_open.h>
#include <syscalls/sys_read.h>
#include <utils/errno.h>
#include <utils/misc.h>
#include <utils/string.h>
#include <utils/sev_snp.h>

static int load_binary(int fd, process* p) {
  void *buf = smalloc(0x1000, MALLOC_NO_ALIGN);
  hp_read(fd, physical(buf), 0x1000);
 
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*) buf;
  if(memcmp(ehdr->e_ident, "\177ELF\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16) != 0)
    return -ENOEXEC;
  p->entry = ehdr->e_entry;
  p->load_addr = 0;
  if(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) return -ENOEXEC;
  if(ehdr->e_type == ET_DYN) p->load_addr = 0x0000555555554000ull; // who care ASLR
  if(ehdr->e_phoff != sizeof(*ehdr)) return -EINVAL;
  if(ehdr->e_phentsize != sizeof(Elf64_Phdr)) return -EINVAL;
  if(ehdr->e_phoff + (uint64_t) ehdr->e_phentsize * ehdr->e_phnum > 0x1000)
    return -EINVAL;

  Elf64_Phdr *phdr = (Elf64_Phdr*) ((uint8_t*) buf + ehdr->e_phoff);
  for(int i = 0; i < ehdr->e_phnum; i++, phdr++)
    if(phdr->p_type == PT_LOAD) {
      uint64_t sz = phdr->p_filesz;
      uint64_t st = p->load_addr + aligndown(phdr->p_vaddr),
               ed = p->load_addr + alignup(phdr->p_vaddr + sz);
      int prot = pf_to_prot(phdr->p_flags);
      /* not a good idea, but it works */

      void *r = sys_mmap(
        (void*) st, sz + (phdr->p_offset & 0xfff), prot,
        MAP_FIXED, fd, phdr->p_offset & -0x1000
      );
      if(r != (void*) st) return (int) (int64_t) r; // error returned by sys_mmap

      if(phdr->p_memsz > sz) {
        uint64_t bss_ed = p->load_addr + alignup(phdr->p_vaddr + phdr->p_memsz);
        if(bss_ed != ed) {
          if(mmap((void*) ed, bss_ed - ed, prot) != (void*) ed)
            return -ENOMEM;
        }
      }
    }
  /* set up stack */
  p->stack_base = 0x00007ffffffff000ull;
  p->stack_size = 0x40000;
  p->rsp = p->stack_base - 0x1000;
  void *st = (void*) (p->stack_base - p->stack_size);
  if(mmap(st, p->stack_size, PROT_RW) != st) return -ENOMEM;
  return 0;
}

static int check_and_get_count(char *const ary[]) {
  write_in_console("before first access string ok\n");
  if(!access_ok(VERIFY_READ, ary, 8)) return -EFAULT;
  write_in_console("after first access string ok\n");
  int i = 0;
  while(*ary != 0) {
    write_in_console(*ary);
    write_in_console("\n");
    if(!access_string_ok(*ary)) return -EFAULT;
    ++ary;
    ++i;
    if(!access_ok(VERIFY_READ, ary, 8)) return -EFAULT;
  }
  return i;
}

#define STACK_ALLOC(sp, len) ({ sp -= len ; (uint64_t*) sp; })
#define ROUNDDOWN(sp) sp &= -0x10

static int create_elf_info(process *p, char *const argv[], char *const envp[]) {
  /* we must push strings first */
  unsigned char buffer[20] = {0};
  uint64_to_string((uint64_t)&argv,buffer);
  write_in_console("argv address:0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  int argc = check_and_get_count(argv);
  uint64_to_string((uint64_t)argc,buffer); 
  write_in_console("argc: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  if(argc < 0) return argc;
  int envc = check_and_get_count(envp);
  uint64_to_string((uint64_t)envc,buffer); 
  write_in_console("envc: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  if(envc < 0) return envc;
  char **copy = (char**) kmalloc((argc + envc + 2) * sizeof(char*), MALLOC_NO_ALIGN);
  for(int i = envc - 1; i >= 0; i--) {
    uint64_t len = strlen(envp[i]) + 1;
    copy[argc + 1 + i] = (char*) STACK_ALLOC(p->rsp, len);
    memcpy(copy[argc + 1 + i], envp[i], len);
  }
  for(int i = argc - 1; i >= 0; i--) {
    uint64_t len = strlen(argv[i]) + 1;
    copy[i] = (char*) STACK_ALLOC(p->rsp, len);
    memcpy(copy[i], argv[i], len);
  }

  /* program is happier if rsp is aligned */
  /* The final rsp must be 16-byte aligned, so we calculate how many bytes
   * will be copied later, and round the rsp here.
   */
  ROUNDDOWN(p->rsp);
  if((argc + 1 + envc + 1 + 1) & 1) STACK_ALLOC(p->rsp, 8);
  /* push envp and argv onto stack */
  for(int i = argc + envc + 1; i >= 0; i--)
    *(char**) STACK_ALLOC(p->rsp, 8) = copy[i];
  kfree(copy);
  /* last step, push argc onto it */
  *(uint64_t*) STACK_ALLOC(p->rsp, 8) = argc;
  return 0;
}


/* can only be used in kernel_main */
int sys_execve(const char *path, char *const argv[], char *const envp[]) {
  int fd = sys_open(path);
  if(fd < 0) return fd;
  process p;
  int ret = load_binary(fd, &p);
  if(ret < 0) return ret;
  sys_close(fd);
  if(create_elf_info(&p, argv, envp)) return -EFAULT;
  /* this is an execve call so we can ignore the saved registers (rip, rsp) */
  unsigned char buffer[20] = {0};
  write_in_console("Ready to return to the userspace\n");
  write_in_console("process entry:0x");
  uint64_to_string(p.entry,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  write_in_console("process load_addr:0x");
  uint64_to_string(p.load_addr,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  write_in_console("process rsp:0x");
  uint64_to_string(p.rsp,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  write_in_console("process stack_base:0x");
  uint64_to_string(p.stack_base,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  write_in_console("process stack_size:0x");
  uint64_to_string(p.stack_size,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  write_in_console("\n");
  for(int i=0;i<100;i++){
    uint64_to_string(*(uint64_t *)((p.entry+p.load_addr+i*8)),buffer);
    write_in_console((char*)buffer);
    write_in_console("\n");
  }

  write_in_console("\n");
  
  uint64_t efer = read_msr(IA32_EFER);
  write_in_console("IA32_EFER:0x");
  uint64_to_string(efer,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");


  uint64_t star = read_msr(0xc0000081);
  write_in_console("STAR:0x");
  uint64_to_string(star,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_t lstar = read_msr(0xc0000082);
  write_in_console("LSTAR:0x");
  uint64_to_string(lstar,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_t cstar = read_msr(0xc0000083);
  write_in_console("CSTAR:0x");
  uint64_to_string(cstar,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_t sfmasr = read_msr(0xc0000084);
  write_in_console("SFMASK:0x");
  uint64_to_string(sfmasr,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_t U_CET = read_msr(0x6A0);
  write_in_console("U_CET:0x");
  uint64_to_string(U_CET,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_t ssp_cpl3 = read_msr(0x6A7);
  write_in_console("ssp_cpl3:0x");
  uint64_to_string(ssp_cpl3,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");
  
  uint64_t cpl = 0xff;
  asm volatile(
    "mov %0, cs;"
    "and %0, 0x03;"
    :"=r"(cpl)
    ::
  );
  write_in_console("cpl:0x");
  uint64_to_string(cpl,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  asm volatile(
    "mov [rip + kernel_stack], rsp;"
    "mov rcx, %[entry];" /* rip */
    "mov r11, 0x2;"      /* rflags */
    "mov rsp, %[rsp];"
    /* clean up registers */
    "xor rax, rax;"
    "xor rbx, rbx;"
    "xor rdx, rdx;"
    "xor rdi, rdi;"
    "xor rsi, rsi;"
    "xor rbp, rbp;"
    "xor r8, r8;"
    "xor r9, r9;"
    "xor r10, r10;"
    "xor r12, r12;"
    "xor r13, r13;"
    "xor r14, r14;"
    "xor r15, r15;"
    "xor rbp, rbp;"
    ".byte 0x48;"
    "sysretq"
    :: [entry]"r"(p.entry + p.load_addr), [rsp]"r"(p.rsp)
    : "r11", "rcx"
  );
  /* never reached */
  return -EPERM;
}
