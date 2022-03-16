
PBKDF2.axf:     file format elf32-littlearm


Disassembly of section .text:

00000bf0 <test_hmac_isha>:
     bf0:	b5f0      	push	{r4, r5, r6, r7, lr}
     bf2:	b09b      	sub	sp, #108	; 0x6c
     bf4:	af02      	add	r7, sp, #8
     bf6:	2328      	movs	r3, #40	; 0x28
     bf8:	18fb      	adds	r3, r7, r3
     bfa:	4a3d      	ldr	r2, [pc, #244]	; (cf0 <test_hmac_isha+0x100>)
     bfc:	ca13      	ldmia	r2!, {r0, r1, r4}
     bfe:	c313      	stmia	r3!, {r0, r1, r4}
     c00:	ca13      	ldmia	r2!, {r0, r1, r4}
     c02:	c313      	stmia	r3!, {r0, r1, r4}
     c04:	ca13      	ldmia	r2!, {r0, r1, r4}
     c06:	c313      	stmia	r3!, {r0, r1, r4}
     c08:	2303      	movs	r3, #3
     c0a:	657b      	str	r3, [r7, #84]	; 0x54
     c0c:	2300      	movs	r3, #0
     c0e:	65fb      	str	r3, [r7, #92]	; 0x5c
     c10:	2300      	movs	r3, #0
     c12:	65bb      	str	r3, [r7, #88]	; 0x58
     c14:	e05d      	b.n	cd2 <test_hmac_isha+0xe2>
     c16:	2428      	movs	r4, #40	; 0x28
     c18:	1939      	adds	r1, r7, r4
     c1a:	6dba      	ldr	r2, [r7, #88]	; 0x58
     c1c:	0013      	movs	r3, r2
     c1e:	005b      	lsls	r3, r3, #1
     c20:	189b      	adds	r3, r3, r2
     c22:	009b      	lsls	r3, r3, #2
     c24:	585b      	ldr	r3, [r3, r1]
     c26:	0018      	movs	r0, r3
     c28:	f002 fd26 	bl	3678 <strlen>
     c2c:	0003      	movs	r3, r0
     c2e:	653b      	str	r3, [r7, #80]	; 0x50
     c30:	1939      	adds	r1, r7, r4
     c32:	6dba      	ldr	r2, [r7, #88]	; 0x58
     c34:	0013      	movs	r3, r2
     c36:	005b      	lsls	r3, r3, #1
     c38:	189b      	adds	r3, r3, r2
     c3a:	009b      	lsls	r3, r3, #2
     c3c:	18cb      	adds	r3, r1, r3
     c3e:	3304      	adds	r3, #4
     c40:	681b      	ldr	r3, [r3, #0]
     c42:	0018      	movs	r0, r3
     c44:	f002 fd18 	bl	3678 <strlen>
     c48:	0003      	movs	r3, r0
     c4a:	64fb      	str	r3, [r7, #76]	; 0x4c
     c4c:	1939      	adds	r1, r7, r4
     c4e:	6dba      	ldr	r2, [r7, #88]	; 0x58
     c50:	0013      	movs	r3, r2
     c52:	005b      	lsls	r3, r3, #1
     c54:	189b      	adds	r3, r3, r2
     c56:	009b      	lsls	r3, r3, #2
     c58:	18cb      	adds	r3, r1, r3
     c5a:	3308      	adds	r3, #8
     c5c:	6819      	ldr	r1, [r3, #0]
     c5e:	2614      	movs	r6, #20
     c60:	19bb      	adds	r3, r7, r6
     c62:	2214      	movs	r2, #20
     c64:	0018      	movs	r0, r3
     c66:	f003 f98d 	bl	3f84 <hexstr_to_bytes>
     c6a:	0025      	movs	r5, r4
     c6c:	1939      	adds	r1, r7, r4
     c6e:	6dba      	ldr	r2, [r7, #88]	; 0x58
     c70:	0013      	movs	r3, r2
     c72:	005b      	lsls	r3, r3, #1
     c74:	189b      	adds	r3, r3, r2
     c76:	009b      	lsls	r3, r3, #2
     c78:	5858      	ldr	r0, [r3, r1]
     c7a:	6d3c      	ldr	r4, [r7, #80]	; 0x50
     c7c:	1979      	adds	r1, r7, r5
     c7e:	6dba      	ldr	r2, [r7, #88]	; 0x58
     c80:	0013      	movs	r3, r2
     c82:	005b      	lsls	r3, r3, #1
     c84:	189b      	adds	r3, r3, r2
     c86:	009b      	lsls	r3, r3, #2
     c88:	18cb      	adds	r3, r1, r3
     c8a:	3304      	adds	r3, #4
     c8c:	681a      	ldr	r2, [r3, #0]
     c8e:	6cf9      	ldr	r1, [r7, #76]	; 0x4c
     c90:	003b      	movs	r3, r7
     c92:	9300      	str	r3, [sp, #0]
     c94:	000b      	movs	r3, r1
     c96:	0021      	movs	r1, r4
     c98:	f003 f890 	bl	3dbc <hmac_isha>
     c9c:	19b9      	adds	r1, r7, r6
     c9e:	003b      	movs	r3, r7
     ca0:	2214      	movs	r2, #20
     ca2:	0018      	movs	r0, r3
     ca4:	f003 f94d 	bl	3f42 <cmp_bin>
     ca8:	1e03      	subs	r3, r0, #0
     caa:	d009      	beq.n	cc0 <test_hmac_isha+0xd0>
     cac:	6dba      	ldr	r2, [r7, #88]	; 0x58
     cae:	4911      	ldr	r1, [pc, #68]	; (cf4 <test_hmac_isha+0x104>)
     cb0:	4b11      	ldr	r3, [pc, #68]	; (cf8 <test_hmac_isha+0x108>)
     cb2:	0018      	movs	r0, r3
     cb4:	f002 fc7c 	bl	35b0 <_printf>
     cb8:	6dfb      	ldr	r3, [r7, #92]	; 0x5c
     cba:	3301      	adds	r3, #1
     cbc:	65fb      	str	r3, [r7, #92]	; 0x5c
     cbe:	e005      	b.n	ccc <test_hmac_isha+0xdc>
     cc0:	6dba      	ldr	r2, [r7, #88]	; 0x58
     cc2:	490c      	ldr	r1, [pc, #48]	; (cf4 <test_hmac_isha+0x104>)
     cc4:	4b0d      	ldr	r3, [pc, #52]	; (cfc <test_hmac_isha+0x10c>)
     cc6:	0018      	movs	r0, r3
     cc8:	f002 fc72 	bl	35b0 <_printf>
     ccc:	6dbb      	ldr	r3, [r7, #88]	; 0x58
     cce:	3301      	adds	r3, #1
     cd0:	65bb      	str	r3, [r7, #88]	; 0x58
     cd2:	6dba      	ldr	r2, [r7, #88]	; 0x58
     cd4:	6d7b      	ldr	r3, [r7, #84]	; 0x54
     cd6:	429a      	cmp	r2, r3
     cd8:	db9d      	blt.n	c16 <test_hmac_isha+0x26>
     cda:	6d7a      	ldr	r2, [r7, #84]	; 0x54
     cdc:	6dfb      	ldr	r3, [r7, #92]	; 0x5c
     cde:	1ad3      	subs	r3, r2, r3
     ce0:	425a      	negs	r2, r3
     ce2:	4153      	adcs	r3, r2
     ce4:	b2db      	uxtb	r3, r3
     ce6:	0018      	movs	r0, r3
     ce8:	46bd      	mov	sp, r7
     cea:	b019      	add	sp, #100	; 0x64
     cec:	bdf0      	pop	{r4, r5, r6, r7, pc}
     cee:	46c0      	nop			; (mov r8, r8)
     cf0:	00004cc8 	.word	0x00004cc8
     cf4:	00004e10 	.word	0x00004e10
     cf8:	00004c78 	.word	0x00004c78
     cfc:	00004c90 	.word	0x00004c90
