TARGET := hypervisor.elf
SRCS := hypervisor.c hypercall.c pc_sysfw_ovmf.c tdvf.c tdvf-hob.c uuid.c e820_memory_layout.c
DEPS := definition.h debug.h e820_memory_layout.h
CFLAGS := -Wall
PKGS=glib-2.0
CFLAGS+=$(shell pkg-config --cflags $(PKGS))
CFLAGS+= -g
LDFLAGS+=$(shell pkg-config --libs $(PKGS))

ifdef KVM_DEBUG
CFLAGS += -DDEBUG
endif

all: $(TARGET)

$(TARGET): $(SRCS) $(DEPS)
	$(CC) $^ $(CFLAGS) -o $@ $(LIBS) $(LDFLAGS)

debug:
	$(MAKE) KVM_DEBUG=1

clean:
	$(RM) $(TARGET)
