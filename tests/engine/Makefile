CC       = gcc
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS   = -std=gnu17 -Wall -Wextra -O1 -g -pthread $(SAN)
CPPFLAGS = -D_GNU_SOURCE -I../../engine/include
LDFLAGS  = -pthread $(SAN)

SRC   = ../../engine/src
BUILD = build
TESTS = $(BUILD)/test_errors $(BUILD)/test_config $(BUILD)/test_pktring

.PHONY: all test engine clean

all: $(TESTS)

test: $(TESTS)
	@for t in $(TESTS); do $$t || exit 1; done

engine:
	./run_engine.sh

$(BUILD)/test_errors: test_errors.c $(SRC)/errors.c check.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_errors.c $(SRC)/errors.c $(LDFLAGS)

$(BUILD)/test_config: test_config.c $(SRC)/config.c $(SRC)/errors.c check.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_config.c $(SRC)/config.c \
		$(SRC)/errors.c $(LDFLAGS)

$(BUILD)/test_pktring: test_pktring.c $(SRC)/pktring.c $(SRC)/errors.c check.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_pktring.c $(SRC)/pktring.c \
		$(SRC)/errors.c $(LDFLAGS)

clean:
	rm -rf $(BUILD)
