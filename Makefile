LIB_DIR ?= lib
BIN_DIR ?= bin
CC      ?= gcc
CFLAGS  ?= -std=gnu11 -Wall -g
PKGCONF ?= pkg-config

# Create bin directory and make submodule
ifeq "$(wildcard $(BIN_DIR) )" ""
$(info Creating makefile for all object files...)
$(shell mkdir -p $(BIN_DIR))
$(shell $(CC) -MM $(LIB_DIR)/*.c |                              \
sed -E "s@^(.*):@$(BIN_DIR)/\1:@g" |                            \
awk 'NR>1&&/:/{printf "\t$$(CC) $$(CFLAGS) -o $$@ -c %s\n%s\n", \
"$$(patsubst $(BIN_DIR)/%.o,$(LIB_DIR)/%.c,$$@)", $$0}          \
NR==1||!/:/{print $$0}                                          \
END{printf "\t$$(CC) $$(CFLAGS) -c -o $$@ %s\n",                \
"$$(patsubst $(BIN_DIR)/%.o,$(LIB_DIR)/%.c,$$@)"}'              \
> $(BIN_DIR)/objects.mk)
endif

# Is DPDK installed on ./dpdk/build/install?
ifeq "$(wildcard ./dpdk/build/install )" ""
$(error "You must run build.sh before make.")
endif

# Set package config path to dkd install dir
PCFILES=$(shell find $(PWD)/dpdk/build/install/ -name "*.pc")
PKG_CONFIG_PATH=$(shell dirname $(PCFILES) | sort | uniq)

# Build using pkg-config variables if possible
ifneq ($(shell export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) && \
               $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found. Did you run build.sh?")
endif

LDFLAGS:=$(shell export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) && \
                 $(PKGCONF) --static --libs libdpdk)
CFLAGS +=$(shell export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) && \
                 $(PKGCONF) --cflags libdpdk)

# Search for all objects
SOURCES:=$(wildcard $(LIB_DIR)/*.c)
OBJECTS:=$(patsubst $(LIB_DIR)/%.c,$(BIN_DIR)/%.o,$(wildcard $(LIB_DIR)/*.c))

release: $(BIN_DIR)/client.exe
debug:   $(BIN_DIR)/client.exe

$(BIN_DIR)/client.exe: $(OBJECTS)
	$(CC) $(CFLAGS) $+ $(LDFLAGS) -o $@

# Include submodule with rules to create objects
include $(BIN_DIR)/objects.mk

# Target specific variables
release: CFLAGS += -O2 -DNDEBUG
debug:   CFLAGS += -O0

clean:
	rm -rf $(BIN_DIR)
