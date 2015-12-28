#ifndef	_INLINE_HOOK_H_
#define	_INLINE_HOOK_H_

#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <CydiaSubstrate.h>

class NDKHOOK
{
public:
	int mode;
	void *org_addr;
	unsigned char *opcode;
	int jmpcode;

	int	Hook_normal(void *org, void *now);
	int Unhook_normal();
	__attribute__((naked)) void Hook_normal_ret();

	int Hook_advance(void *org, void *now, void **old);
	int Unhook_advance();

	int Hook_flow();
	
	NDKHOOK()
	{
		mode=0;
		opcode = (unsigned char *)mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	}

	~NDKHOOK()
	{
		munmap(opcode, PAGE_SIZE);
	}
};

extern "C" {
	void InitFlowHook();
}

#endif