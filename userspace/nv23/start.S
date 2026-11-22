/* uClibc ARM EABI entry for a helper linked against the vendor libraries.
 * argc is at sp, argv follows. __uClibc_main(main, argc, argv, init, fini,
 * rtld_fini, stack_end); no constructors of our own. */
.syntax unified
.arm
.global _start
.type _start,%function
_start:
    mov fp, #0
    mov lr, #0
    ldr r1, [sp], #4
    mov r2, sp
    push {r2}
    push {r0}
    mov r3, #0
    push {r3}
    ldr r0, =main
    b __uClibc_main
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
