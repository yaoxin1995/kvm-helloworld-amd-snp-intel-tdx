TARGET := kernel.elf

SRCS := entry.s kernel_main.c
OBJS :=
DEPS := $(wildcard ./**/*.d)
SUBOBJS := syscalls/syscalls.a hypercalls/hypercalls.a mm/mm.a elf/elf.a utils/utils.a

CFLAGS := -Wall  -Werror -fPIE -pie -masm=intel -nostdlib -Os -I.
LDFLAGS := -ffreestanding -fno-builtin -Tlinker.script

.PRECIOUS: %.o
all: $(TARGET)

%.elf: $(SRCS) $(OBJS) $(SUBOBJS)
	$(CC) $(CFLAGS) $^ -o $@ -Xlinker --oformat=elf64-x86-64 $(LDFLAGS) -Bsymbolic -z notext

%.o: %.s
	$(AS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -MMD -MP $< -o $@

$(SUBOBJS): FORCE
	$(MAKE) -C $(dir $@) $(notdir $@)

.PHONY: clean
clean:
	dirname $(SUBOBJS) | xargs -n 1 $(MAKE) clean -C
	$(RM) $(OBJS) $(TARGET) $(DEPS)

FORCE:
