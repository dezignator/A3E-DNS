# c/reference/Makefile
#
# Build the C reference implementations and their tests.
#
# Every source file is compiled with -O2 -Wall -Wextra -Werror because
# the reference implementation should not have warnings that a reviewer
# might mistake for a known issue. If the compiler ever emits a warning
# on this code, it is a bug in the code, not in the compiler.

CC      := cc
CFLAGS  := -O2 -std=c99 -Wall -Wextra -Werror -pedantic -Iinclude
LDFLAGS := -lm
BINDIR  := build

LIB_SRCS := src/field.c src/ntt.c src/sampler.c src/pcap_reader.c
LIB_OBJS := $(LIB_SRCS:src/%.c=$(BINDIR)/%.o)

TEST_NTT_SRC     := test/test_ntt.c
TEST_NTT_BIN     := $(BINDIR)/test_ntt

TEST_SAMPLER_SRC := test/test_sampler.c
TEST_SAMPLER_BIN := $(BINDIR)/test_sampler

.PHONY: all clean test

all: $(BINDIR) $(TEST_NTT_BIN) $(TEST_SAMPLER_BIN)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%.o: src/%.c | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_NTT_BIN): $(TEST_NTT_SRC) $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_SAMPLER_BIN): $(TEST_SAMPLER_SRC) $(LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: all
	@echo "Running NTT tests:"
	@$(TEST_NTT_BIN)
	@echo "Running sampler tests:"
	@$(TEST_SAMPLER_BIN)

clean:
	rm -rf $(BINDIR)
