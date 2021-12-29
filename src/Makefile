CLANG ?= clang
LLVM_STRIP ?= llvm-strip
OUTPUT := $(abspath .output)
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = perfbuf-output

ifeq ($(V),1)
	Q =
else
	Q = @
	MAKEFLAGES += --no-print-directory
endif

.PHONE:all
all : $(APPS)

$(OUTPUT) : $(LIBBPF_SRC)
	$(Q)mkdir -p $(OUTPUT)/libbpf

# Build final application
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# Build user-space code
$(OUTPUT)/%.o : %.c $(wildcard %.h) | $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c, $^) -o $@

# 用户态的代码，依赖于skeletons
$(patsubst %,$(OUTPUT)/%.o,$(APPS)) : %.o : %.skel.h

# Generate BPF skeletons
$(OUTPUT)/%.skel.h : $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build BPF code
$(OUTPUT)/%.bpf.o : %.bpf.c $(LIBBPF_OBJ) common.h
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -I. -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Build libbpf
$(LIBBPF_OBJ):$(wildcard $(LIBBPF_SRC)/*.[ch]) $(LIBBPF_SRC)/Makefile | $(OUTPUT)/libbpf
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
	OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
	INCLUDEDIR= LIBDIR= UAPIDIR= \
	install

.PHONY : clean
clean:
	$(Q)rm -rf $(OUTPUT) $(APPS)