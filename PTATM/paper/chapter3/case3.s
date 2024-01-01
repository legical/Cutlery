
case3.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	f3 0f 1e fa          	endbr64 
   4:	55                   	push   %rbp
   5:	48 89 e5             	mov    %rsp,%rbp
   8:	89 7d ec             	mov    %edi,-0x14(%rbp)
   b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
   f:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  16:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  1d:	eb 1e                	jmp    3d <main+0x3d>
  1f:	8b 45 fc             	mov    -0x4(%rbp),%eax
  22:	83 e0 01             	and    $0x1,%eax
  25:	85 c0                	test   %eax,%eax
  27:	74 0a                	je     33 <main+0x33>
  29:	8b 45 fc             	mov    -0x4(%rbp),%eax
  2c:	01 c0                	add    %eax,%eax
  2e:	01 45 f8             	add    %eax,-0x8(%rbp)
  31:	eb 06                	jmp    39 <main+0x39>
  33:	8b 45 fc             	mov    -0x4(%rbp),%eax
  36:	01 45 f8             	add    %eax,-0x8(%rbp)
  39:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  3d:	83 7d fc 63          	cmpl   $0x63,-0x4(%rbp)
  41:	7e dc                	jle    1f <main+0x1f>
  43:	8b 45 f8             	mov    -0x8(%rbp),%eax
  46:	5d                   	pop    %rbp
  47:	c3                   	ret    
