#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "../../src/usecboot.h"
#include "root_pkey.h"

#define IMAGE_BASE 0x00010000
volatile uint8_t* lm3s6965_uart0 = (uint8_t*)0x4000C000;

void *memcpy(void *dst, const void *src, size_t len);
void uart_puts(const char *str);

int prep(const struct usecboot_slot *slot)
{
	(void)slot;
	usecboot_log("PREP called\n");
	return USECBOOTERR_NONE;
}

int read(const struct usecboot_slot *slot, uint32_t start, void *data,
	 size_t len)
{
	(void)slot;
	void *flash_ptr = (void *)(IMAGE_BASE + start);

	usecboot_log("Doing read at %x len %d\n", IMAGE_BASE + start, len);
	memcpy(data, flash_ptr, len);
	return USECBOOTERR_NONE;
}

void boot(const struct usecboot_slot *slot)
{
	(void)slot;
	usecboot_log("BOOT called\n");
}

void clean(const struct usecboot_slot *slot)
{
	(void)slot;
	usecboot_log("CLEAN called\n");
}

struct usecboot_slotapi api = {
	.prep = prep,
	.read = read,
	.boot = boot,
	.clean = clean,
};

int usecboot_get_slot(uint8_t idx, struct usecboot_slot *slot)
{
	if (idx != 0) {
		return -USECBOOTERR_ENOENT;
	}

	slot->api = &api;

	return USECBOOTERR_NONE;
}

int usecboot_get_rejected_pubkey(uint32_t idx, uint8_t *pubkey, size_t len)
{
	(void)idx;
	(void)pubkey;
	(void)len;
	return -USECBOOTERR_ENOENT;
}

int usecboot_get_rootpkey(void *pkey, size_t len)
{
	const char *rootpkey = USECBOOT_ROOTPKEY;
	uint8_t *pk = (uint8_t *)pkey;

	if (len != sizeof(USECBOOT_ROOTPKEY) - 1) {
		return -USECBOOTERR_EINVAL;
	}

	memcpy(pk, rootpkey, len);
	return 0;
}

int main(void)
{
	uart_puts("=== uSECboot Start - Test on Cortex-M3 ===\r\n");
	usecboot_boot();
	uart_puts("=== uSECboot - End ===\r\n");
    	return 0;
}

/* provide a minimal memcpy and logging routine */
void *memcpy(void *dst, const void *src, size_t len)
{
	uint8_t *dst8 = (uint8_t *)dst;
	const uint8_t *src8 = (const uint8_t *)src;

	for (size_t i = 0; i < len; i++) {
		dst8[i] = src8[i];
	}

	return dst;
}

void uart_putc(char c)
{
	*lm3s6965_uart0 = c;
}

void uart_puts(const char *str) {
    while (*str) {
        uart_putc(*str++);
    }
}

void uart_puthex(uint32_t val) {
    const char hex_chars[] = "0123456789ABCDEF";

    uart_putc('0');
    uart_putc('x');

    for (int i = 28; i >= 0; i -= 4) {
        uart_putc(hex_chars[(val >> i) & 0xF]);
    }
}

void uart_putdec(uint32_t val) {
    char buffer[10];
    char *p = buffer + 9;
    *p = '\0';

    do {
        *--p = '0' + (val % 10);
        val /= 10;
    } while (val > 0);

    uart_puts(p);
}

void uart_vprintf(const char *fmt, va_list args)
{
	while (*fmt) {
		if (*fmt == '%') {
	    	fmt++;
	    	switch (*fmt) {
	        case 'd': {
        	        uint32_t val = va_arg(args, uint32_t);
                	uart_putdec(val);
                    	break;
                }
                case 'x': {
                    	uint32_t val = va_arg(args, uint32_t);
                    	uart_puthex(val);
			break;
                }
                case 's': {
			char *str = va_arg(args, char*);
			uart_puts(str);
			break;
                }
                case 'c': {
			char c = (char)va_arg(args, int);
                	uart_putc(c);
                	break;
                }
                default:
			uart_putc(*fmt);
            }
        } else {
        	uart_putc(*fmt);
        }
        fmt++;
    }
}

void uart_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_vprintf(fmt, args);
	va_end(args);
}

void usecboot_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_vprintf(fmt, args);
	va_end(args);
}