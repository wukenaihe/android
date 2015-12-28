#include <android/log.h>
#include "inline.h"


#define LOG_TAG "wetest"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <CydiaSubstrate.h>
	   
static ssize_t (*old_send) (int , const char* , int , int );
static ssize_t (*old_recv) (int , char* , int , int );

static void inline cache_flush(unsigned int begin, unsigned int end)
{	
	const int syscall = 0xf0002;
	__asm __volatile (
		"mov	 r0, %0\n"			
		"mov	 r1, %1\n"
		"mov	 r7, %2\n"
		"mov     r2, #0x0\n"
		"svc     0x00000000\n"
		:
		:	"r" (begin), "r" (end), "r" (syscall)
		:	"r0", "r1", "r7"
		);
}

static unsigned int GetSpValue(unsigned int offset)
{
	__asm__ __volatile__(
		"mov r3, sp\n\t"
		"ldr r0, [r3, r0]"
	);
}

static void SetSpValue(unsigned int offset, unsigned int value)
{
	__asm__ __volatile__(
		"mov r3, sp\n\t"
		"str r1, [r3, r0]"
	);
}

__attribute__((naked)) void NDKHOOK::Hook_normal_ret()
{
	__asm__ __volatile__(
		"mov r0, %[jmpcode] \n\t"
		"bx r0"
		:
		:[jmpcode]"r"(jmpcode)
		:
	);
}


int NDKHOOK::Hook_normal(void *org, void *now)
{
	//保存原始地址，用于Unhook
	org_addr = org;

	if ((unsigned long)org % 4 == 0)
	{
		//arm模式
		mode=1;
		//设置权限
		if (mprotect((void *)(((unsigned long)org/PAGE_SIZE)*PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC)!=0)
			return 0;

		//配置jmp代码
		memcpy(opcode, "\xff\x5f\x2d\xe9\x04\xf0\x1f\xe5\x00\x00\x00\x00\xff\x5f\xbd\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x04\xf0\x1f\xe5\x00\x00\x00\x00", 32);
		memcpy(&opcode[16], org, 8);
		*(unsigned long *)&opcode[8] = (unsigned long)now;
		*(unsigned long *)&opcode[28] = (unsigned long)org+8;
		jmpcode = (unsigned int)opcode+12;

		//替换原函数头部
		unsigned char hook_code[8]={0x00};
		memcpy(hook_code, "\x04\xf0\x1f\xe5\x00\x00\x00\x00", 8);
		*(unsigned long *)&hook_code[4] = (unsigned long)opcode;
		memcpy(org, hook_code, 8);

		//更新指令缓存
		cache_flush((long int)org_addr, (long int)org_addr+8);

		#ifdef DEBUG_MODE
		LOGD("[+] Hook normal in arm end ...\n");
		#endif

		return 1;
	}
	else
	{
		//thumb模式
		mode=2;
		//设置权限
		if (mprotect((void *)(((unsigned long)org/PAGE_SIZE)*PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC)!=0)
			return 0;

		org = (void *)((unsigned long)org-1);

		//配置jmp代码
		memcpy(opcode, "\x80\x00\xbd\xe8\xff\x5f\x2d\xe9\x04\xf0\x1f\xe5\x00\x00\x00\x00\xff\x5f\xbd\xe8\x04\xf0\x1f\xe5\x00\x00\x00\x00", 28);
		*(unsigned long *)&opcode[12]=(unsigned long)now;
		*(unsigned long *)&opcode[24]=(unsigned long)opcode+29;
		memcpy((void *)&opcode[28], org, 12);
		memcpy((void *)&opcode[40], "\xdf\xf8\x00\xf0\x00\x00\x00\x00", 8);
		*(unsigned long *)&opcode[44]=(unsigned long)org+13;
		jmpcode = (unsigned int)opcode+16;
        
		//替换原函数头部
		unsigned char hook_code[12]={0x00};
		memcpy((void *)hook_code, "\x80\xb4\x01\x4f\x38\x47\x38\x47\x00\x00\x00\x00", 12);
		*(unsigned long *)&hook_code[8]=(unsigned long)opcode;
		memcpy(org, hook_code, 12);

		cache_flush((long int)org, (long int)org+12);

		#ifdef DEBUG_MODE
		LOGD("[+] Hook normal in thumb end ...\n");
		#endif

		return 1;
	}
	
	return 0;

}

int NDKHOOK::Unhook_normal()
{
	if (mode==1)
	{
		memcpy(org_addr, &opcode[16], 8);
		cache_flush((long int)org_addr, (long int)org_addr+8);
		#ifdef DEBUG_MODE
		LOGD("[+] UnHook normal in arm end...\n");
		#endif
	}
	else
	{
		memcpy((void *)((unsigned long)org_addr-1), (void *)&opcode[28], 12);
		cache_flush((long int)org_addr-1, (long int)org_addr-1+12);
		#ifdef DEBUG_MODE
		LOGD("[+] UnHook normal in thumb end...\n");
		#endif
	}

	return 0;
}

int NDKHOOK::Hook_advance(void *org, void *now, void **old)
{

     LOGD("Hook_advance start \n");
	 
	//保存原始地址
	org_addr = org;
	
	if ((unsigned long)org % 4 == 0)
	{
	 
	    LOGD("Hook_advance in arm \n");
		
		//arm模式
		mode=1;

		//设置权限
		if (mprotect((void *)(((unsigned long)org/PAGE_SIZE)*PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC)!=0)
			return 0;

		//配置jmp代码
		memcpy(opcode, org, 8);
		memcpy(&opcode[8], "\x04\xf0\x1f\xe5\x00\x00\x00\x00", 8);
		*(unsigned long *)&opcode[12]=(unsigned long)org+8;

		*old=opcode;
		cache_flush((long int)opcode, (long int)opcode+16);

		//替换原函数头部
		unsigned char hook_code[8]={0x00};
		memcpy((void *)hook_code, "\x04\xf0\x1f\xe5\x00\x00\x00\x00", 8);
		*(unsigned long *)&hook_code[4]=(unsigned long)now;
		memcpy(org, hook_code, 8);

		cache_flush((long int)org, (long int)org+8);

		#ifdef DEBUG_MODE
		LOGD("[+] Hook advance in arm end ...\n");
		#endif
	}
	else
	{
	
	    LOGD("Hook_advance in thumb \n");
	 
		//thumb模式
		mode=2;

		org = (void *)((unsigned long)org-1);

		//设置权限
		if (mprotect((void *)((((unsigned long)org)/PAGE_SIZE)*PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC)!=0)
			return 0;
		
		//配置jmp代码
		memcpy(opcode, "\x80\x00\xbd\xe8\x04\xf0\x1f\xe5\x00\x00\x00\x00", 12);
		*(unsigned long *)&opcode[8]=(unsigned long)now;
		memcpy((void *)&opcode[12], org, 12);
		memcpy((void *)&opcode[24], "\xdf\xf8\x00\xf0\x00\x00\x00\x00", 8);
		*(unsigned long *)&opcode[28]=(unsigned long)org+13;

		*old=(void *)((unsigned long)opcode+13);
		cache_flush((long int)opcode, (long int)opcode+32);

		//替换原函数头部
		unsigned char hook_code[12]={0x00};
		memcpy((void *)hook_code, "\x80\xb4\x01\x4f\x38\x47\x38\x47\x00\x00\x00\x00", 12);
		*(unsigned long *)&hook_code[8]=(unsigned long)opcode;
		memcpy(org, hook_code, 12);

		cache_flush((long int)org, (long int)org+12);


		#ifdef DEBUG_MODE
		LOGD("[+] Hook advance in thumb end ...\n");
		#endif
	}

	return 1;
}

int NDKHOOK::Unhook_advance()
{
	if (mode==1)
	{
		memcpy(org_addr, opcode, 8);
		cache_flush((long int)org_addr, (long int)org_addr+8);
		#ifdef DEBUG_MODE
		LOGD("[+] UnHook advance in arm end...\n");
		#endif
	}
	else
	{
		memcpy((void *)((unsigned long)org_addr-1), (void *)&opcode[12], 12);
		cache_flush((long int)org_addr-1, (long int)org_addr-1+12);
		#ifdef DEBUG_MODE
		LOGD("[+] UnHook advance in thumb end...\n");
		#endif
	}

	return 0;
}

ssize_t my_send (int fd, const char* buf , int nBytes , int flags){

	LOGD("This is MySend");
	struct sockaddr_in serv, guest;
	char serv_ip[20];
	char guest_ip[20];
	int serv_len = sizeof(serv);
	int guest_len = sizeof(guest);
	getsockname(fd, (struct sockaddr *)&serv, &serv_len);
	getpeername(fd, (struct sockaddr *)&guest, &guest_len);
	inet_ntop(AF_INET, &serv.sin_addr, serv_ip, sizeof(serv_ip));
	inet_ntop(AF_INET, &guest.sin_addr, guest_ip, sizeof(guest_ip));
	//printf("host %s:%d guest %s:%d\n", serv_ip, ntohs(serv.sin_port), guest_ip, ntohs(guest.sin_port));
	LOGD("host %s:%d guest %s:%d\n", serv_ip, ntohs(serv.sin_port), guest_ip, ntohs(guest.sin_port));

	return 0;
}

ssize_t my_recv (int fd, char* buf , int nBytes , int flags){

	LOGD("This is MyRecv");
    
	struct sockaddr_in serv, guest;
	char serv_ip[20];
	char guest_ip[20];
	int serv_len = sizeof(serv);
	int guest_len = sizeof(guest);
	getsockname(fd, (struct sockaddr *)&serv, &serv_len);
	getpeername(fd, (struct sockaddr *)&guest, &guest_len);
	inet_ntop(AF_INET, &serv.sin_addr, serv_ip, sizeof(serv_ip));
	inet_ntop(AF_INET, &guest.sin_addr, guest_ip, sizeof(guest_ip));
	//printf("host %s:%d guest %s:%d\n", serv_ip, ntohs(serv.sin_port), guest_ip, ntohs(guest.sin_port));
	LOGD("host %s:%d guest %s:%d\n", serv_ip, ntohs(serv.sin_port), guest_ip, ntohs(guest.sin_port));

	return 0;
}

int NDKHOOK::Hook_flow()
{
	
	
	void * pLibc = dlopen("/system/lib/libc.so",RTLD_LAZY);
	void * pMySend  = dlsym(pLibc ,  "send" );
	void * pMyRecv  = dlsym(pLibc ,  "recv" );

	if(pLibc != NULL){

	     LOGD("libc is not NULL");

	}else{

		LOGD("libc is NULL");

	}

	if(pMySend != NULL){

	     LOGD("pMySend is not NULL");

	}else{

		LOGD("pMySend is NULL");

	}

	if(pMyRecv != NULL){

	     LOGD("pMyRecv is not NULL");

	}else{

		LOGD("pMyRecv is NULL");

	}

	Hook_advance (pMySend, (void *)my_send, (void **)&old_send);

	LOGD("Hook send success");
		
	//Hook_advance (pMyRecv, (void *)my_recv, (void **)&old_recv);
	
	LOGD("Hook recv success");
	
	LOGD("NO Hook");
	
	return 0;
	
}


void InitFlowHook(){

	LOGD("InitFlowHook");
	
	
		void * pLibc = dlopen("/system/lib/libc.so",RTLD_LAZY);
	void * pMySend  = dlsym(pLibc ,  "send" );
	void * pMyRecv  = dlsym(pLibc ,  "recv" );

	if(pLibc != NULL){

	     LOGD("libc is not NULL");

	}else{

		LOGD("libc is NULL");

	}

	if(pMySend != NULL){

	     LOGD("pMySend is not NULL");

	}else{

		LOGD("pMySend is NULL");

	}

	if(pMyRecv != NULL){

	     LOGD("pMyRecv is not NULL");

	}else{

		LOGD("pMyRecv is NULL");

	}
	
	
	MSHookFunction(pMySend, (void *)my_send, (void **)&old_send);
    //NDKHOOK flowHook;
	//flowHook.Hook_flow();
		
}