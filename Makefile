CC=gcc
CFLAGS=-I.
DEPS=
OBJ=status_code.o \
    server.o
    
USERID=123456789

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: server
server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -lpthread

clean:
	rm -rf *.o server *.tar.gz

dist: tarball
tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz --exclude=./.vagrant . && mv /tmp/$(USERID).tar.gz .