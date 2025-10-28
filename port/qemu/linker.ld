MEMORY {
        FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
        SRAM  (rw) : ORIGIN = 0x2000F000, LENGTH = 4K
}

SECTIONS {
        . = 0x00000000;
        .text : {
            KEEP(*(.vectors))
            *(.startup)
            *(.text)
            *(.text.*)           /* Add this for function sections */
            *(.rodata)
            *(.rodata.*)         /* Add this for read-only data sections */
            . = ALIGN(4);
        } > FLASH

        .data : {
            . = ALIGN(4);
            _sram_sdata = .;
            *(.data)
            *(.data.*)           /* ← CRITICAL: Collect all data sections */
            . = ALIGN(4);
            _sram_edata = .;
        } > SRAM AT > FLASH

        _flash_sdata = LOADADDR(.data);

        .bss : {
            . = ALIGN(4);
            _sram_sbss = .;
            *(.bss)
            *(.bss.*)            /* ← CRITICAL: Collect all BSS sections */
            *(COMMON)
            . = ALIGN(4);
            _sram_ebss = .;
        } > SRAM

        _sram_stacktop = ORIGIN(SRAM) + LENGTH(SRAM);
}