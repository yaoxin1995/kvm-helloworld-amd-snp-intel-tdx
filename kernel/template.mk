CSRCS	:= $(wildcard *.c)
SSRCS	:= $(wildcard *.s) $(wildcard *.asm)
OBJS	:= $(SSRCS:.s=.o) $(CSRCS:.c=.o) $(SSRCS:.asm=.o)
DEPS	:= $(CSRCS:.c=.d)

CFLAGS := -nostdlib -Os -Wall -Werror -fPIE -pie -m64 -masm=intel -I..

all: $(TARGET)

-include $(DEPS)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -MMD -MP $<

%.o: %.s
	$(AS) $^ -o $@
	
%.o: %.asm
	$(AS) $^ -o $@ 

.PHONY: clean
clean:
	$(RM) $(DEPS) *.o $(TARGET)
