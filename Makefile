CC ?= gcc
CFLAGS += -Wall -Os -flto
# CFLAGS += -DWINDOWSMAIN
LDFLAGS += -s -lws2_32 -lwininet  -flto
# LDFLAGS += -mwindows

.PHONY: all
all: nanomet.exe wnanomet.exe

.PHONY: clean
clean:
	rm -f nanomet.exe wnanomet.exe

nanomet.exe: nanomet.c
	$(CC) $(CFLAGS) nanomet.c -o nanomet.exe $(LDFLAGS)
wnanomet.exe: nanomet.c
	$(CC) $(CFLAGS) -DWINDOWSMAIN nanomet.c -o wnanomet.exe $(LDFLAGS) -mwindows
