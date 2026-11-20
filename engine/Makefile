CC       = gcc
CSTD     = -std=gnu17
WARN     = -Wall -Wextra -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
CFLAGS   = $(CSTD) $(WARN) -O2 -g -pthread
CPPFLAGS = -D_GNU_SOURCE -Iinclude -MMD -MP
LDFLAGS  = -pthread
LDLIBS   = -lpcap -lcap

BUILD = build
OBJ_D = $(BUILD)/obj
BIN   = $(BUILD)/monnett

COMPONENTS = capturer parser

SRCS = src/main.c \
       $(sort $(wildcard src/common/*.c)) \
       $(foreach c,$(COMPONENTS),$(sort $(wildcard src/components/$(c)/*.c)))

OBJS = $(SRCS:src/%.c=$(OBJ_D)/%.o)

ifeq ($(V),1)
Q =
else
Q = @
endif

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	@echo "  LD  $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_D)/%.o: src/%.c
	@mkdir -p $(@D)
	@echo "  CC  $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d)
