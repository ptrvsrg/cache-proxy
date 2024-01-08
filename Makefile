CC = gcc
CFLAGS = -O2 -Wall -Werror -Wextra -pedantic
DEF = -D_GNU_SOURCE
BIN_NAME = cache-proxy

BUILD_DIR = ./build
INCLUDE_DIR = ./include
SRC_DIR = ./src
LIB_DIR = ./lib
TEST_DIR = ./test

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

.PHONY: build
build:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(DEF) -I$(INCLUDE_DIR) -I$(LIB_DIR)/picohttpparser $(SRC_DIR)/* $(LIB_DIR)/picohttpparser/picohttpparser.c -o $(BUILD_DIR)/$(BIN_NAME) $(LINK_PTHREAD)

.PHONY: run
run:
	$(BUILD_DIR)/$(BIN_NAME) $(PORT)

.PHONY: test
test:
	@bash test/tests.sh

.PHONY: help
help:
	@echo "Available commands:"
	@echo "    make clean"
	@echo "        Clean generated files"
	@echo "    make build"
	@echo "        Build the executable file"
	@echo "    make run PORT=<int>"
	@echo "        Run the built executable file"
	@echo "    make test"
	@echo "        Test the running executable file"
	@echo "    make help"
	@echo "        Display this message"

.DEFAULT_GOAL := help