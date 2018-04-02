CC = gcc
CFLAGS = -g -w -I/usr/local/include
CHMOD := $(shell which chmod)
SETCAP := $(shell which setcap)
USER := $(shell whoami)

# Name of text file containing build number.
BUILD_NUMBER_FILE=build-number.txt

# Create an auto-incrementing build number.

BUILD_DATE := $(shell date +'%Y%m%d')
BUILD_NUMBER := $(shell cat $(BUILD_NUMBER_FILE))

BUILD_NUMBER_LDFLAGS  = -D__BUILD_DATE=$(BUILD_DATE)
BUILD_NUMBER_LDFLAGS += -D__BUILD_NUMBER=$(BUILD_NUMBER) 

# Build number file.  Increment if any object file changes.

all: sshpot
	@if ! test -f $(BUILD_NUMBER_FILE); then echo 0 > $(BUILD_NUMBER_FILE); fi
	@echo $$(($$(cat $(BUILD_NUMBER_FILE)) + 1)) > $(BUILD_NUMBER_FILE)

sshpot: main.o auth.o uuid4.o stats.o 
	@echo Building SSHPot N: $$(cat $(BUILD_NUMBER_FILE)) on $$(date +'%Y%m%d')
	$(CC) $(CFLAGS) $(BUILD_NUMBER_LDFLAGS) $^ -lssh -lssl -lcrypto -ljson-c  $(LDFLAGS) -o $@

main.o: main.c config.h
	$(CC) $(CFLAGS) $(BUILD_NUMBER_LDFLAGS) -c main.c

auth.o: auth.c uuid4.c stats.c auth.h config.h stats.h
	$(CC) $(CFLAGS) -c auth.c

install:
	echo This is not actually installing or starting sshpot. 
	echo It allows it to bind to ports < 1024 even without being root.
	echo Binaries and config won't be moved.
	@if [ $(USER) != "root" ]; then echo make install must be run as root.; false; fi
	$(CHMOD) 755 sshpot
	$(SETCAP) 'cap_net_bind_service=+ep' sshpot

clean:
	\/bin/rm -f *.o
