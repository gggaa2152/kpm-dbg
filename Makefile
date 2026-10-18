# kpm_dbg - all-in-one kernel debug toolkit
#
# Build requires KernelPatch source tree (KP_DIR) and an aarch64 cross gcc.
#   make TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch

ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS += -fno-pic -fno-stack-protector -fno-asynchronous-unwind-tables \
          -fno-unwind-tables -mcmodel=large -mgeneral-regs-only

objs := src/kpm_dbg.o

all: kpm_dbg.kpm

kpm_dbg.kpm: ${objs}
	${CC} -r -o $@ $^

src/%.o: src/%.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -Tkpm.lds -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm
	find . -name "*.o" | xargs rm -f
