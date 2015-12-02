  # the compiler: gcc for C program
  CC = gcc

  VERIFIER_ROOT=..
  BIN=$(VERIFIER_ROOT)/bin

  # compiler flags:
  #  -g    adds debugging information to the executable file
  LDFLAGS  := -pie -z noexecstack -z relro -z now
  CFLAGS  = -g -Wformat -Wformat-security -fPIE -fPIC -fstack-protector -O2 -D FORTIFY_SOURCE=2

  LIBS = -lxml2 -lcrypto

  CURR_DIR = `pwd`

  INCLUDES = -I/usr/include/libxml2/ -I$(CURR_DIR)

  # the build target executable:
  TARGET = verifier

  all: $(TARGET)

  $(TARGET): $(TARGET).c
	mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(TARGET).c  $(INCLUDES) $(LIBS) -o $(BIN)/$(TARGET) $(LDFLAGS)

  clean:
	rm -rf $(BIN)
