#include <stdint.h>

#define PERIPH_BASE        0x40000000UL

#define AHB1PERIPH_BASE    (PERIPH_BASE + 0x00020000UL)
#define APB1PERIPH_BASE    (PERIPH_BASE + 0x00000000UL)

#define RCC_BASE           (AHB1PERIPH_BASE + 0x3800UL)
#define GPIOA_BASE         (AHB1PERIPH_BASE + 0x0000UL)
#define USART2_BASE        (APB1PERIPH_BASE + 0x4400UL)

#define RCC_AHB1ENR        (*(volatile unsigned long *)(RCC_BASE + 0x30))
#define RCC_APB1ENR        (*(volatile unsigned long *)(RCC_BASE + 0x40))

#define GPIOA_MODER        (*(volatile unsigned long *)(GPIOA_BASE + 0x00))
#define GPIOA_AFRL         (*(volatile unsigned long *)(GPIOA_BASE + 0x20))

#define USART2_SR          (*(volatile unsigned long *)(USART2_BASE + 0x00))
#define USART2_DR          (*(volatile unsigned long *)(USART2_BASE + 0x04))
#define USART2_BRR         (*(volatile unsigned long *)(USART2_BASE + 0x08))
#define USART2_CR1         (*(volatile unsigned long *)(USART2_BASE + 0x0C))
#define USART2_CR2         (*(volatile unsigned long *)(USART2_BASE + 0x10))
#define USART2_CR3         (*(volatile unsigned long *)(USART2_BASE + 0x14))

#define GPIOA_ODR          (*(volatile uint32_t*)(GPIOA_BASE + 0x14))

const uint8_t __attribute__((section(".firmware_header"))) header[512];

void led_init(void);
void led_toggle(int cnt);
void uart_init(void);
void uart_puts(const char *str);

int main(void)
{
	led_init();
	led_toggle(1);
	uart_init();
	uart_puts("Hello World\r\n");
    	return 0;
}

void led_init(void)
{
	// Setup LED
	RCC_AHB1ENR |= (1 << 0);
	GPIOA_MODER |= (1 << 10);
}

void led_toggle(int cnt)
{
	while (cnt != 0) {
		GPIOA_ODR ^= (1 << 5);
        	for(volatile int i = 0; i < 10000; i++);
		cnt--;
	}
}

void uart_clear_dr(void)
{
	// Read the DR register to clear any stale data
	volatile uint32_t dummy = USART2_DR;
	(void)dummy; // Prevent unused variable warning
}

void uart_init(void) {
	// Enable clocks
	RCC_AHB1ENR |= (1 << 0);
	RCC_APB1ENR |= (1 << 17);

	// Configure GPIO
	GPIOA_MODER &= ~((3 << (2*2)) | (3 << (3*2)));
	GPIOA_MODER |=  ((2 << (2*2)) | (2 << (3*2)));
	GPIOA_AFRL &= ~((0xF << (2*4)) | (0xF << (3*4)));
	GPIOA_AFRL |=  ((7 << (2*4)) | (7 << (3*4)));

	// Clear any stale data from DR
	uart_clear_dr();

	// Set baud rate
	USART2_BRR = 0x08B;

	// Clear any pending status flags by reading SR
	volatile uint32_t status = USART2_SR;
	(void)status;

	USART2_CR1 |= (1 << 13);  // UE first
	for(volatile int i = 0; i < 1000; i++);  // Wait for baud rate to stabilize

	// NOW enable transmitter
	USART2_CR1 |= (1 << 3) | (1 << 2);  // TE + RE
}

void uart_putc(char c)
{
	while (!(USART2_SR & (1 << 7)));  // Wait for TXE
	USART2_DR = c;
}

void uart_puts(const char *str) {
	while (*str) {
		uart_putc(*str++);
	}
}