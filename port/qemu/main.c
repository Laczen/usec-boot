#include "../../src/usecboot.h"
#include <stdint.h>

int usecboot_get_slot(uint8_t idx, struct usecboot_slot *slot)
{
	(void)idx;
	(void)slot;

	return -USECBOOTERR_ENOENT;
}

int usecboot_get_rejected_pubkey(uint32_t idx, uint8_t *pubkey, size_t len)
{
	(void)idx;
	(void)pubkey;
	(void)len;
	return -USECBOOTERR_ENOENT;
}

volatile uint8_t* lm3s6965_uart0 = (uint8_t*)0x4000C000;

void uart0_print(const char* msg)
{
    while(*msg)
    {
        *lm3s6965_uart0 = *msg;
        msg++;
    }
}

int main(void)
{
	uart0_print("=== uSECboot Start - Test on Cortex-M3 ===\r\n");
	usecboot_boot();
	uart0_print("=== uSECboot - End ===\r\n");
    	return 0;
}
