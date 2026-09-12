# SPDX-License-Identifier: MIT
CC = gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?= -lcrypto

all: rinvalidate

obj:
	@if not exist obj mkdir obj

obj/rinvalidate.o: src/rinvalidate.c include/rin_formats_v3.h | obj
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

rinvalidate: obj/rinvalidate.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	@if exist obj rmdir /s /q obj
	@if exist rinvalidate del /q rinvalidate
	@if exist rinvalidate.exe del /q rinvalidate.exe

.PHONY: all clean
