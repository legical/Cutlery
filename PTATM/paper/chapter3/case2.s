
case2.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	f3 0f 1e fa          	endbr64 
   4:	55                   	push   %rbp
   5:	48 89 e5             	mov    %rsp,%rbp
   8:	89 7d ec             	mov    %edi,-0x14(%rbp)
   b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
   f:	83 7d ec 01          	cmpl   $0x1,-0x14(%rbp)
  13:	7f 07                	jg     1c <main+0x1c>
  15:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  1a:	eb 23                	jmp    3f <main+0x3f>
  1c:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  23:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  2a:	eb 0a                	jmp    36 <main+0x36>
  2c:	8b 45 fc             	mov    -0x4(%rbp),%eax
  2f:	01 45 f8             	add    %eax,-0x8(%rbp)
  32:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  36:	83 7d fc 63          	cmpl   $0x63,-0x4(%rbp)
  3a:	7e f0                	jle    2c <main+0x2c>
  3c:	8b 45 f8             	mov    -0x8(%rbp),%eax
  3f:	5d                   	pop    %rbp
  40:	c3                   	ret    
