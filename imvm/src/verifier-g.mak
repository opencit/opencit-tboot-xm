  # the compiler: gcc for C program
  CC = gcc

  VERIFIER_ROOT=..
  BIN=$(VERIFIER_ROOT)/bin
  SAFESTRING=./SafeStringLibrary/
  SAFESTRING_INCLUDE=$(SAFESTRING)/include/
  LIBXML_INCLUDE=/usr/include/libxml2/

  # compiler flags:
  #  -g    adds debugging information to the executable file
  LDFLAGS  := -pie -z noexecstack -z relro -z now
  CFLAGS  = -g -Wformat -Wformat-security -fPIE -fPIC -fstack-protector -O2 -D FORTIFY_SOURCE=2

  LIBS = -lxml2 -lcrypto -lSafeStringRelease

  CURR_DIR = `pwd`

  INCLUDES = -I$(LIBXML_INCLUDE) -I$(CURR_DIR) -I$(SAFESTRING_INCLUDE)

  # the build target executable:
  TARGET = verifier

  all: $(TARGET)

  $(TARGET): $(TARGET).c
	mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(TARGET).c  $(INCLUDES) -L$(SAFESTRING) $(LIBS) -o $(BIN)/$(TARGET) $(LDFLAGS)

  clean:
	rm -rf $(BIN)
