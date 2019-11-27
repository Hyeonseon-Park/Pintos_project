#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);

void
check_user_vaddr(const void *vaddr)
{
  if (!is_user_vaddr(vaddr))
    exit(-1);
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_user_vaddr(f->esp + 4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      check_user_vaddr(f->esp + 4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      check_user_vaddr(f->esp + 4);
      f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      check_user_vaddr(f->esp + 20);
      check_user_vaddr(f->esp + 24);
      check_user_vaddr(f->esp + 28);
      write((int)*(uint32_t *)(f->esp + 20), (void *) *(uint32_t *)(f->esp + 24), (unsigned) *((uint32_t *)(f->esp + 28)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
  }
}
void
halt(void)
{
  shutdown_power_off();
}

void
exit (int status)
{
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t
exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

int
wait (pid_t pid)
{
  return process_wait(pid);
}

int
read (int fd, void *buffer, unsigned length)
{

}
int
write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}

bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);



  /*
  printf("\nsystemcall num: %d\n", *(uint32_t*)(f->esp));
  printf ("system call!\n");
  thread_exit ();
  */
