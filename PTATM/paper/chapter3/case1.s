
case1.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	f3 0f 1e fa          	endbr64 
   4:	55                   	push   %rbp
   5:	48 89 e5             	mov    %rsp,%rbp
   8:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
   f:	c7 45 f8 02 00 00 00 	movl   $0x2,-0x8(%rbp)
  16:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
  1a:	74 06                	je     22 <main+0x22>
  1c:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  20:	eb 06                	jmp    28 <main+0x28>
  22:	8b 45 f4             	mov    -0xc(%rbp),%eax
  25:	29 45 f8             	sub    %eax,-0x8(%rbp)
  28:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  2f:	eb 10                	jmp    41 <main+0x41>
  31:	8b 45 fc             	mov    -0x4(%rbp),%eax
  34:	01 45 f4             	add    %eax,-0xc(%rbp)
  37:	8b 45 fc             	mov    -0x4(%rbp),%eax
  3a:	29 45 f8             	sub    %eax,-0x8(%rbp)
  3d:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  41:	83 7d fc 63          	cmpl   $0x63,-0x4(%rbp)
  45:	7e ea                	jle    31 <main+0x31>
  47:	83 7d f4 04          	cmpl   $0x4,-0xc(%rbp)
  4b:	77 3c                	ja     89 <main+0x89>
  4d:	8b 45 f4             	mov    -0xc(%rbp),%eax
  50:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  57:	00 
  58:	48 8d 05 00 00 00 00 	lea    0x0(%rip),%rax        # 5f <main+0x5f>
  5f:	8b 04 02             	mov    (%rdx,%rax,1),%eax
  62:	48 98                	cltq   
  64:	48 8d 15 00 00 00 00 	lea    0x0(%rip),%rdx        # 6b <main+0x6b>
  6b:	48 01 d0             	add    %rdx,%rax
  6e:	3e ff e0             	notrack jmp *%rax
  71:	83 6d f4 01          	subl   $0x1,-0xc(%rbp)
  75:	eb 18                	jmp    8f <main+0x8f>
  77:	83 6d f4 02          	subl   $0x2,-0xc(%rbp)
  7b:	eb 12                	jmp    8f <main+0x8f>
  7d:	83 6d f4 03          	subl   $0x3,-0xc(%rbp)
  81:	eb 0c                	jmp    8f <main+0x8f>
  83:	83 6d f4 04          	subl   $0x4,-0xc(%rbp)
  87:	eb 06                	jmp    8f <main+0x8f>
  89:	d1 65 f4             	shll   -0xc(%rbp)
  8c:	eb 01                	jmp    8f <main+0x8f>
  8e:	90                   	nop
  8f:	8b 45 f4             	mov    -0xc(%rbp),%eax
  92:	5d                   	pop    %rbp
  93:	c3                   	ret    
