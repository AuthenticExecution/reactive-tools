old-cmd-./ta1.o := arm-linux-gnueabihf-gcc -std=gnu99 -fdiagnostics-show-option -Wall -Wcast-align -Werror-implicit-function-declaration -Wextra -Wfloat-equal -Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-format-attribute -Wmissing-include-dirs -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wswitch-default -Wwrite-strings -Wno-missing-field-initializers -Wno-format-zero-length -Wredundant-decls -Wold-style-definition -Wstrict-aliasing=2 -Wundef -mcpu=cortex-a15 -O0 -g3 -fpic -mthumb -fno-short-enums -fno-common -mno-unaligned-access -mfloat-abi=hard -funsafe-math-optimizations -funwind-tables -MD -MF ./.ta1.o.d -MT ta1.o -nostdinc -isystem /optee/toolchains/aarch32/bin/../lib/gcc/arm-none-linux-gnueabihf/10.2.1/include -I./include -I./. -DARM32=1 -D__ILP32__=1 -DMBEDTLS_SELF_TEST -DTRACE_LEVEL=4 -I. -I/optee/optee_os/out/arm/export-ta_arm32/include -DCFG_TA_DYNLINK=1 -DCFG_TEE_TA_LOG_LEVEL='4' -DCFG_SYSTEM_PTA=1 -DCFG_UNWIND=1 -DCFG_ARM32_ta_arm32=1 -DCFG_TA_MBEDTLS=1 -DCFG_TA_MBEDTLS_SELF_TEST=1 -DCFG_TA_MBEDTLS_MPI=1 -DCFG_TA_FLOAT_SUPPORT=1 -D__FILE_ID__=ta1_c -c ta1.c -o ta1.o
