.POSIX:

.SUFFIXES: .c .o

CC=clang
AR=llvm-ar
COBJS=ttc-http.o
INCLUDES=-I./
TARGET=ttc-http.so.0.4
TARGET_STATIC=ttc-http.a

INSTALL_PREFIX=/usr/local

EXAMPLE=ttc-http-example
EXAMPLEOBJS=examples/example.o
EXAMPLELIBS=-lssl -lcrypto

all: $(TARGET) $(TARGET_STATIC) $(EXAMPLE)

.c.o:
	@echo $(CC) $@
	@$(CC) $(INCLUDES) -c $< -o $@

$(TARGET_STATIC): $(COBJS)
	@echo $(AR) $@
	@$(AR) -rcs $@ $(COBJS)

$(TARGET): $(COBJS)
	@echo linking $@
	@$(CC) -shared $(COBJS) -o $@

$(EXAMPLE): $(EXAMPLEOBJS) $(COBJS)
	@echo linking $@
	@$(CC) $(EXAMPLELIBS) $(EXAMPLEOBJS) $(COBJS) -o $@

install: $(TARGET) $(TARGET_STATIC)
	install -m 755 $(TARGET) /usr/local/lib/lib$(TARGET)
	install -m 755 $(TARGET_STATIC) /usr/local/lib/lib$(TARGET_STATIC)
	install -m 644 ttc-http.h /usr/local/include/
	ln -s /usr/local/lib/lib$(TARGET) /usr/local/lib/libttc-http.so

uninstall:
	@rm /usr/local/lib/lib$(TARGET) /usr/local/lib/lib$(TARGET_STATIC) /usr/local/lib/libttc-http.so


clean:
	@echo cleaning $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
	@rm $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
