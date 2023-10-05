.POSIX:

.SUFFIXES: .c .o

CC=clang
AR=llvm-ar
COBJS=lchttp.o
INCLUDES=-I./
TARGET=lchttp.so.0.4
TARGET_STATIC=lchttp.a

INSTALL_PREFIX=/usr/local

EXAMPLE=lchttp-example
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
	install -m 644 lchttp.h /usr/local/include/
	ln -s /usr/local/lib/lib$(TARGET) /usr/local/lib/liblchttp.so

uninstall:
	@rm /usr/local/lib/lib$(TARGET) /usr/local/lib/lib$(TARGET_STATIC) /usr/local/lib/liblchttp.so


clean:
	@echo cleaning $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
	@rm $(EXAMPLE) $(EXAMPLEOBJS) $(COBJS) $(TARGET) $(TARGET_STATIC)
