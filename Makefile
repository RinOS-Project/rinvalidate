# SPDX-License-Identifier: Apache-2.0
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?= -lcrypto
RINOS_SDK_INCLUDE ?= ../../RinOS-SDK/include

# GNU make supplies a built-in `CC=cc`.  On Windows that command is often not
# installed even when the selected GCC toolchain is available, so use gcc for
# the built-in default while still honoring an explicit CC override.
ifeq ($(origin CC),default)
CC = gcc
endif

ifeq ($(OS),Windows_NT)
OBJDIR ?= obj/windows
MKDIR_P = if not exist "$(1)" mkdir "$(1)"
RM_RF = if exist "$(1)" rmdir /s /q "$(1)"
RM_F = if exist "$(1)" del /q "$(1)"
else
OBJDIR ?= obj/posix
MKDIR_P = mkdir -p "$(1)"
RM_RF = rm -rf "$(1)"
RM_F = rm -f "$(1)"
endif

RINVALIDATE_OBJECT = $(OBJDIR)/rinvalidate.o

all: rinvalidate

$(OBJDIR):
	$(call MKDIR_P,$@)

$(RINVALIDATE_OBJECT): src/rinvalidate.c $(RINOS_SDK_INCLUDE)/rin/formats_v3.h | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(RINOS_SDK_INCLUDE) -c $< -o $@

rinvalidate: $(RINVALIDATE_OBJECT)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	$(call RM_RF,obj)
	$(call RM_F,rinvalidate)
	$(call RM_F,rinvalidate.exe)

.PHONY: all clean
