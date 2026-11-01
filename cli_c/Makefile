# PacketMedic TUI (pmtui) - no external libraries required.
#   Linux/macOS:            make
#   Windows (MSYS2/MinGW):  mingw32-make
CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -Wall -Wextra -Wformat=2 -Wno-format-truncation -Wshadow -fstack-protector-strong
SRC     := $(wildcard src/*.c)

ifeq ($(OS),Windows_NT)
  TARGET  := pmtui.exe
  LDFLAGS += -static
  LDLIBS  += -lws2_32 -lshell32 -ladvapi32
else
  TARGET  := pmtui
  CFLAGS  += -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2
endif

all: $(TARGET)

$(TARGET): $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	-rm -f pmtui pmtui.exe

.PHONY: all clean
