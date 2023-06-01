CC:=gcc
LDFLAGS:=`pkg-config --silence-errors --keep-system-libs --libs openssl`
all:
	$(CC) cudydecrypt.c -o cudy-bdinfo $(LDFLAGS)
