BUILD := build
ARCH_INCLUDE ?= /usr/include/$(shell gcc -dumpmachine)
CFLAGS := -O2 -g -Wall -Wextra
.PHONY: all clean test
all: $(BUILD)/firewall.bpf.o $(BUILD)/loader
$(BUILD):
	mkdir -p $@
$(BUILD)/firewall.bpf.o: bpf/firewall.bpf.c | $(BUILD)
	clang $(CFLAGS) -target bpf -mcpu=v3 -I$(ARCH_INCLUDE) -c $< -o $@
$(BUILD)/loader: bpf/loader.c | $(BUILD)
	cc $(CFLAGS) $< -lbpf -lelf -lz -o $@
test:
	python3 -m unittest discover -s tests -v
clean:
	rm -rf $(BUILD)
