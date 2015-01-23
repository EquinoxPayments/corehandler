/*
 * Copyright (c) 2014 Equinox Payments, LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "config.h"
#include "proc.h"
#include "util.h"
#include "xmalloc.h"

/*
 * References:
 *	ARM Architecture Reference Manual
 *	Procedure Call Standard for the ARM Architecture
 */

/*
 * A decoded ARM instruction.
 */
union ins {
	enum instypes {
		INVALID_INSTRUCTION,
		ADD,
		SUB,	/* subtract */
		STM,	/* store multiple registers to main memory */
		LDM,	/* load multiple registers from main memory */
		BL,	/* branch with link */
		BLX1,	/* branch with link and exchange (i.e. potentially switch to Thumb mode) */
		BLX2,
		SWI,	/* software interrupt (a.k.a. SVC) */
		BX,	/* branch and exchange */
	} type;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;	/* condition field */
		unsigned	 I	:1;	/* if set -- shifter is an immediate value, otherwise -- a register index */
		unsigned	 S	:1;	/* update CPSR register if set */
		unsigned	 Rn	:4;	/* register containing first operand */
		unsigned	 Rd	:4;	/* destination register */
		unsigned	 shifter:12;	/* shifter operand */
	} add, sub;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;
		unsigned	 P	:1;	/* P, U and W determine addressing mode */
		unsigned	 U	:1;
		unsigned	 W	:1;
		unsigned	 Rn	:4;	/* base register */
		unsigned	 regs	:16;
	} ldm, stm;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;
		signed		 immed	:24;	/* immediate value; offset from PC */
	} bl;
	struct {
		enum instypes	 type;
		unsigned	 H	:1;	/* 1 if destination is Thumb code */
		signed		 immed	:24;
	} blx1;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;
		unsigned	 Rm	:4;	/* register containing address of target instruction */
	} blx2;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;
		unsigned	 immed	:24;
	} swi;
	struct {
		enum instypes	 type;
		unsigned	 cond	:4;
		unsigned	 Rm	:4;	/* register with branch target address */
		unsigned	 thumb	:1;	/* if set, target is a Thumb instruction  */
	} bx;
};

/* ARM general purpose registers. */
enum {
	R0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13, SP = R13,	/* stack pointer */
	R14, LR = R14,	/* link register (holds return address) */
	R15, PC = R15,	/* program counter */
};

/*
 * Return a decoded ARM instruction.
 *
 * Magic numbers from ARM Architecture Reference Manual.
 */
static union ins
decode(word_t word)
{
	union ins	 i;

	if ((word & 0xde00000) == 0x800000 && (word & 0x2000090) != 0x90)
		i.type = ADD;
	else if ((word & 0xde00000) == 0x400000 && (word & 0x2000090) != 0x90)
		i.type = SUB;
	else if ((word & 0xe100000) == 0x8000000
	    && ((word & 0x400000) == 0 || (word & 0x400000) == 0x400000))
		i.type = STM;
	else if ((word & 0xe500000) == 0x8100000
	    || (word & 0xe708000) == 0x8500000
	    || (word & 0xe508000) == 0x8508000)
		i.type = LDM;
	else if ((word & 0xf000000) == 0xb000000)
		i.type = BL;
	else if ((word & 0xfe000000) == 0xfa000000)
		i.type = BLX1;
	else if ((word & 0x0ffffff0) == 0x12fff30)
		i.type = BLX2;
	else if ((word & 0xf000000) == 0xf000000)
		i.type = SWI;
	else if ((word & 0xffffff0) == 0x12fff10)
		i.type = BX;
	else
		i.type = INVALID_INSTRUCTION;

	/* Return a word where range of bits hi through lo are set. */
	#define R(hi, lo)	((~0 << (lo)) & ~((~0 << hi) << 1))
	/* Return word's bit-field hi through lo, shifted lo bits right. */
	#define F(word, hi, lo)	(((word) & R(hi, lo)) >> lo)

	switch (i.type) {
	case ADD:
	case SUB:
		i.add.cond    = F(word, 31, 28);
		i.add.I       = F(word, 25, 25);
		i.add.S       = F(word, 20, 20);
		i.add.Rn      = F(word, 19, 16);
		i.add.Rd      = F(word, 15, 12);
		i.add.shifter = F(word, 11,  0);
		break;
	case LDM:
	case STM:
		i.ldm.cond    = F(word, 31, 28);
		i.ldm.P       = F(word, 24, 24);
		i.ldm.U       = F(word, 23, 23);
		i.ldm.W       = F(word, 21, 21);
		i.ldm.Rn      = F(word, 19, 16);
		i.ldm.regs    = F(word, 15,  0);
		break;
	case BL:
		i.bl.cond     = F(word, 31, 28);
		i.bl.immed    = F(word, 23,  0);
		break;
	case BLX1:
		i.blx1.H      = F(word, 23,  0);
		i.blx1.immed  = F(word, 23,  0);
		break;
	case BLX2:
		i.blx2.cond   = F(word, 31, 28);
		i.blx2.Rm     = F(word,  3,  0);
		break;
	case SWI:
		i.swi.cond    = F(word, 31, 28);
		i.swi.immed   = F(word, 23,  0);
		break;
	case BX:
		i.bx.cond     = F(word, 31, 28);
		i.bx.Rm       = F(word,  3,  1) << 1;
		i.bx.thumb    = F(word,  0,  0);
		break;
	}

	return i;

	#undef R
	#undef F
}

/*
 * Return the number of bits that are set in i.
 */
static unsigned
count_bits(unsigned i)
{
	unsigned	 n = 0;

	while (i) {
		if (i & 1)
			++n;
		i >>= 1;
	}
	return n;
}

/*
 * Return true if i is a 'SUB SP, SP, N' instruction (i.e. subtract immediate
 * value N from value of SP and save result into SP).
 */
static bool
is_sub_sp_sp_n(union ins i)
{
	return i.type   == SUB
	    && i.sub.Rn == SP
	    && i.sub.Rd == SP;
}

/*
 * Return true if i is a 'push' instruction (i.e. is an STM instruction which
 * uses a particular addressing mode and SP as base register).
 */
static bool
is_push(union ins i)
{
	return i.type   == STM
	    && i.stm.P  == 1
	    && i.stm.U  == 0
	    && i.stm.W  == 1
	    && i.stm.Rn == SP;
}

/*
 * If i is not a 'push' instruction, return 0, otherwise, return the number of
 * registers pushed onto stack.
 */
static unsigned
count_pushed(union ins i)
{
	if (is_push(i))
		return count_bits(i.stm.regs);
	return 0;
}

/*
 * Return true if i is a 'push' instruction and it pushes LR register.
 */
static bool
pushes_lr(union ins i)
{
	return is_push(i)
	    && i.stm.regs & 1<<LR;
}

/*
 * Return true if i is a 'push' instruction and it pushes PC register.
 */
static bool
pushes_pc(union ins i)
{
	return is_push(i)
	    && i.stm.regs & 1<<PC;
}

/*
 * Return true if i is a "pop" instruction (i.e. LDM with base register SP).
 */
static bool
is_pop(union ins i)
{
	return i.type   == LDM
	    && i.ldm.P  == 0
	    && i.ldm.U  == 1
	    && i.ldm.W  == 1
	    && i.ldm.Rn == SP;
}

/*
 * Return the number of registers popped.
 */
static unsigned
count_popped(union ins i)
{
	if (is_pop(i))
		return count_bits(i.ldm.regs);
	return 0;
}

/*
 * Return true if i is a 'pop' instruction and it pops into PC register.
 */
static bool
pops_pc(union ins i)
{
	return is_pop(i)
	    && i.ldm.regs & 1<<PC;
}

/*
 * Return true if i is a 'pop' instruction and it pops LR register.
 */
static bool
pops_lr(union ins i)
{
	return is_pop(i)
	    && i.ldm.regs & 1<<LR;
}

/*
 * Return true if i is a 'ADD SP, SP, N' instruction (i.e. add an immediate
 * value to value of SP register and save result in SP register).
 */
static bool
is_add_sp_sp_n(union ins i)
{
	return i.type   == ADD
	    && i.add.Rn == SP
	    && i.add.Rd == SP;
}

/*
 * Return true if addr points into some executable memory map.
 */
static bool
points_into_code(struct proc *p, word_t addr)
{
	struct map	*m;

	if (addr % sizeof(word_t) != 0)
		return false;

	LIST_FOREACH(m, &p->maps, entry) {
		if (!m->perm.x)
			continue;
		if (addr >= m->start && addr < m->end)
			return true;
	}
	return false;
}

/*
 * Return true if addr looks like a return address.
 */
static bool
is_return_addr(struct proc *p, word_t addr)
{
	word_t		 word;
	union ins	 i;

	if (!points_into_code(p, addr))
		return false;

	addr -= sizeof(word_t);
	word = peek(p, addr);
	if (word == ~0)
		return false;

	i = decode(word);

	switch (i.type) {
	case BL:
	case BLX1:
	case BLX2:
	case SWI:
		return true;
	}
	return false;
}

/*
 * Return true if f seems to be a valid call frame.
 */
static bool
is_valid_frame(struct proc *p, struct frame *f)
{
	word_t	 lraddr; /* address of value of LR saved on the stack frame */
	word_t	 word;

	/*
	 * There may be irregular functions, which do not store LR in the frame,
	 * or don't even create a call frame...
	 */
	if (f->size == 0)
		return true;
	if (f->lrpos == ~0)
		return true;

	/*
	 * But if we got a frame which has an LR stored in it -- check whether
	 * the saved value actually looks like a return address.
	 */
	lraddr = f->sp - (f->lrpos + 1) * sizeof(word_t);
	word = peek(p, lraddr);
	return is_return_addr(p, word);
}

/*
 * Search for prologue of function pointed to by frame->pc, and if successful,
 * fill frame->lrpos, frame->size, adjust frame->sp accordingly and return 
 * true.
 *
 * A typical function prologue looks like this:
 *
 * 0x0000900c <+0>:     push    {r4, r5, r6, r7, r8, r9, r10, r11, lr}
 * ...
 * 0x00009018 <+12>:    sub     sp, sp, #188    ; 0xbc
 * ...
 *
 * The push instruction saves the current values of a set of registers,
 * including LR, onto stack, subtracting 4 (the size of machine word in bytes)
 * from SP for each pushed register.
 * The sub instruction substracts a number from SP, thus allocating space for
 * function's local variables.
 */
static bool
search_prologue(struct proc *p, struct frame *framep)
{
	unsigned	 count = 0;
	word_t		 pc;
	word_t		 word;
	union ins	 i;
	struct frame	 f;

	f = *framep;

	debug("%s(): pc=%08x, sp=%08x", __func__, f.pc, f.sp);

	pc = f.pc;

	if (!points_into_code(p, pc))
		return false;

	f.size = 0;
	f.lrpos = 0;
	while (count++ < MAX_DISASSEMBLE) {
		word = peek(p, pc);
		i = decode(word);

		if (is_sub_sp_sp_n(i))
			f.size += i.sub.shifter;
		else if (is_pop(i) && !pops_pc(i) && !pops_lr(i))
			f.size -= count_popped(i) * sizeof(word_t);
		else if (is_push(i)) {
			f.size += count_pushed(i) * sizeof(word_t);
			if (pushes_lr(i)) {
				if (pushes_pc(i))
					f.lrpos++;
				f.sp += f.size;
				if (is_valid_frame(p, &f)) {
					*framep = f;
					return true;
				} else
					return false;
			}
		}

		pc -= sizeof(word_t);
	}

	return false;
}

/*
 * Search for epilogue of function pointed to by frame->pc, and if successful,
 * fill frame->lrpos, frame->size, adjust frame->sp accordingly and return 
 * true.
 *
 * A typical function epilogue or an early return looks like this:
 *
 * ...
 * 0x00009074 <+104>:   add     sp, sp, #188    ; 0xbc
 * 0x00009078 <+108>:   pop     {r4, r5, r6, r7, r8, r9, r10, r11, pc}
 * ...
 *
 * The add instruction adds a number to SP, thus deallocating space for
 * function's local variables.
 * The pop instruction reads the saved values off stack back into registers,
 * adding 4 (the size of machine word) to SP for each popped register.
 * The value of LR is popped directly into PC register, which results in a jump
 * of execution back to function's caller.
 */
static bool
search_epilogue(struct proc *p, struct frame *framep)
{
	unsigned	 count = 0;
	word_t		 word;
	word_t		 pc;
	union ins	 i;
	struct frame	 f;

	f = *framep;

	debug("%s(): pc=%08x, sp=%08x", __func__, f.pc, f.sp);

	pc = f.pc;

	if (!points_into_code(p, pc))
		return false;

	f.size = 0;
	f.lrpos = ~0;
	while (count++ < MAX_DISASSEMBLE) {
		word = peek(p, pc);
		i = decode(word);

		if (i.type == BX && i.bx.Rm == LR) { /* branch to value of LR */
			break;
		} else if (is_pop(i)) {
			f.size += count_popped(i) * sizeof(word_t);
			debug("%s(): is pop; f.size=%u", __func__, f.size);
			if (pops_pc(i)) {
				f.lrpos = 0;
				break;
			} else if (pops_lr(i)) {
				f.lrpos = 0;
			} else if (f.lrpos != ~0) {
				f.lrpos += count_popped(i);
			}
		} else if (is_add_sp_sp_n(i)) {
			f.size += i.add.shifter;
		} else if (is_push(i)) {
			if (pushes_lr(i)) /* reached prologue of next function */
				break;
			else
				f.size -= count_pushed(i);
		}

		pc += sizeof(word_t);
	}

	f.sp += f.size;
	if (is_valid_frame(p, &f)) {
		*framep = f;
		return true;
	}
	return false;
}

/*
 * Unwind a single call frame.
 * Fill frame->pc; if successful, fill the rest of frame fields and return true.
 */
static bool
unwind_frame(struct proc *p, struct pt_regs *r, struct frame *frame)
{
	typedef bool (search_func)(struct proc *, struct frame *);
	search_func	 *funcs[] = {
		search_epilogue,
		search_prologue,
		NULL
	}, **func;
	word_t		 lraddr;

	frame->pc = r->ARM_pc;
	frame->sp = r->ARM_sp;
	frame->size = 0;
	frame->lrpos = 0;

	for (func = funcs; *func != NULL; ++func) {
		if (!(*func)(p, frame))
			continue;

		if (frame->lrpos == ~0) { /* LR was not stored in call frame */
			if (!is_return_addr(p, r->ARM_lr))
				return false;
		} else {
			lraddr = frame->sp - (frame->lrpos + 1) * sizeof(word_t);
			r->ARM_lr = peek(p, lraddr);
		}
		r->ARM_sp = frame->sp;
		if (r->ARM_pc == r->ARM_lr)
			return false;
		else
			r->ARM_pc = r->ARM_lr;
		return true;
	}

	return false;
}

/*
 * Unwind stack by searching the prologue or epilogue of current function,
 * analasying it and determining function's call frame (e.g. it's size and
 * position of LR register), then doing the same for the function to which LR
 * points to and so on.
 */
static void
smart_unwind(struct proc *p)
{
	struct pt_regs	 r;
	struct frame	*frame;
	int		 count;

	r = p->regs;

	for (count = 0; count < MAX_UNWIND; ++count) {
		frame = xcalloc(1, sizeof *frame);
		TAILQ_INSERT_TAIL(&p->backtrace, frame, entry);
		if (!unwind_frame(p, &r, frame))
			break;
	}
}

/* 
 * Do backtrace by simply searching what looks like return addresses on the stack.
 *
 * Due to the fact that stack may contain return addresses from previous,
 * unrelated code branches, and there may be functions which do not store
 * return address in the call frame -- this approach/algorithm is very
 * inaccurate.
 */
static void
guess_unwind(struct proc *p)
{
	struct pt_regs	 r;
	struct frame	*frame;
	int		 count = 0;
	word_t		 word;

	r = p->regs;

	if (r.ARM_sp < p->stack->start) {
		/* SP doesn't point into stack, this is probably a stack overflow. */
		r.ARM_sp = p->stack->start;
	}

	while (count < MAX_UNWIND && r.ARM_sp < p->stack->end) {
		frame = xcalloc(1, sizeof *frame);
		frame->pc = r.ARM_pc;
		TAILQ_INSERT_TAIL(&p->backtrace, frame, entry);

		if (count == 0 && is_return_addr(p, r.ARM_lr))
			r.ARM_pc = r.ARM_lr;
		else {
			for (; r.ARM_sp < p->stack->end; r.ARM_sp += sizeof(word_t)) {
				word = peek(p, r.ARM_sp);
				if (is_return_addr(p, word)) {
					r.ARM_pc = word;
					break;
				}
			}
		}
		++count;
	}
}

/*
 * Unwind the call frames of proc.
 */
void
unwind(struct proc *p)
{
	word_t	 pc;
	word_t	 sp;

	pc = p->regs.ARM_pc;
	sp = p->regs.ARM_sp;

	/*
	 * smart_unwind() needs valid PC and SP to work, use the inferior
	 * guess_unwind() algorithm if they are not.
	 */
	if (sp < p->stack->start
	    || sp > p->stack->end
	    || !points_into_code(p, pc))
		guess_unwind(p);
	else
		smart_unwind(p);
}

