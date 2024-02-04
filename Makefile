.POSIX:

.SUFFIXES: .c .o

CC=clang
AR=llvm-ar
COBJS=src/ttc-requests.o src/ttc-response.o src/ttc-socket.o
INCLUDES=-I./includes
TARGET=ttc-http.so.0.6
TARGET_STATIC=ttc-http.a

INSTALL_PREFIX=/usr/local

EXAMPLE=ttc-http-example
EXAMPLEOBJS=examples/example.o
EXAMPLELIBS=-lttc-log -lssl -lcrypto

all: $(TARGET) $(TARGET_STATIC) $(EXAMPLE)

.c.o:
	@echo $(CC) $@
	@$(CC) -g -O0 $(INCLUDES) -c $< -o $@

$(TARGET_STATIC): $(COBJS)
	@echo $(AR) $@
	@$(AR) -rcs $@ $(COBJS)

$(TARGET): $(COBJS)
	@echo linking $@
	@$(CC) -shared -g -O0 $(COBJS) -o $@

$(EXAMPLE): $(EXAMPLEOBJS) $(COBJS)
	@echo linking $@
	@$(CC) $(EXAMPLEOBJS) $(COBJS) -o $@ $(EXAMPLELIBS)

install: $(TARGET) $(TARGET_STATIC)
	install -m 755 $(TARGET) /usr/local/lib/lib$(TARGET)
	install -m 755 $(TARGET_STATIC) /usr/local/lib/lib$(TARGET_STATIC)
	cp -r ./includes/ttc-http /usr/local/include/
	ln -s /usr/local/lib/lib$(TARGET) /usr/local/lib/libttc-http.so

uninstall:
	@rm -rf /usr/local/lib/lib$(TARGET) /usr/local/include/ttc-http /usr/local/lib/lib$(TARGET_STATIC) /usr/local/lib/libttc-http.so



clean:
	@echo cleaning $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
	@rm $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
