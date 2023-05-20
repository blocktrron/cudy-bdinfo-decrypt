CC:=gcc
all:
	$(CC) cudydecrypt.c -o cudydecrypt $(pkg-config --silence-errors --libs openssl)
