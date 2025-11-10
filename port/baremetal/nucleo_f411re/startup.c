#include <stdint.h>
#include <stddef.h>

/* Linker symbols - matching your linker script */
extern uint32_t _flash_sdata;    // Start of .data in FLASH (LOADADDR)
extern uint32_t _sram_sdata;     // Start of .data in RAM
extern uint32_t _sram_edata;     // End of .data in RAM
extern uint32_t _sram_sbss;      // Start of .bss in RAM
extern uint32_t _sram_ebss;      // End of .bss in RAM
extern uint32_t _sram_stacktop;  // Top of stack (end of SRAM)

extern int main(void);

/* Unused handler */
void _Unused_Handler(void)
{
	/* Spinning */
	for(;;);
}

/* Exception handlers */
void _Reset_Handler(void);
void _NMI_Handler(void)             __attribute__ ((weak, alias("_Unused_Handler")));
void _Hard_Fault_Handler(void)      __attribute__ ((weak, alias("_Unused_Handler")));
void _Memory_Mgmt_Handler(void)     __attribute__ ((weak, alias("_Unused_Handler")));
void _Bus_Fault_Handler(void)       __attribute__ ((weak, alias("_Unused_Handler")));
void _Usage_Fault_Handler(void)     __attribute__ ((weak, alias("_Unused_Handler")));
void _SVCall_Handler(void)          __attribute__ ((weak, alias("_Unused_Handler")));
void _Debug_Monitor_Handler(void)   __attribute__ ((weak, alias("_Unused_Handler")));
void _PendSV_Handler(void)          __attribute__ ((weak, alias("_Unused_Handler")));
void _SysTick_Handler(void)         __attribute__ ((weak, alias("_Unused_Handler")));

/* Vector table - use .vectors section to match linker script */
__attribute__ ((section(".vectors"), used))
void (* const _exceptions[])(void) = {
	(void (*)(void))&_sram_stacktop,  // Initial stack pointer
	_Reset_Handler,                   // Reset handler
	_NMI_Handler,                     // NMI
	_Hard_Fault_Handler,              // Hard Fault
	_Memory_Mgmt_Handler,             // Memory Management
	_Bus_Fault_Handler,               // Bus Fault
	_Usage_Fault_Handler,             // Usage Fault
	0,                                // Reserved
	0,                                // Reserved
	0,                                // Reserved
	0,                                // Reserved
	_SVCall_Handler,                  // SVCall
	_Debug_Monitor_Handler,           // Debug Monitor
	0,                                // Reserved
	_PendSV_Handler,                  // PendSV
	_SysTick_Handler                  // SysTick
};

/* Reset Handler - use .startup section to match linker script */
__attribute__ ((section(".startup")))
void _Reset_Handler(void)
{
	/* Initialize .data section (copy from FLASH to RAM) */
	uint32_t *src = &_flash_sdata;
	uint32_t *dst = &_sram_sdata;
	uint32_t size = (uint32_t)(&_sram_edata - &_sram_sdata);

	for (uint32_t i = 0; i < size; i++) {
		dst[i] = src[i];
	}

	/* Initialize .bss section (zero it) */
	uint32_t *bss_start = &_sram_sbss;
	uint32_t bss_size = (uint32_t)(&_sram_ebss - &_sram_sbss);

	for (uint32_t i = 0; i < bss_size; i++) {
		bss_start[i] = 0;
	}

	/* Call main() */
	main();

	/* If main returns, loop forever */
	for (;;);
}