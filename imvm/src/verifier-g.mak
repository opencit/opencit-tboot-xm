  # the compiler: gcc for C program
  CC = gcc

  VERIFIER_ROOT=..
  BIN=$(VERIFIER_ROOT)/bin

  # compiler flags:
  #  -g    adds debugging information to the executable file
  CFLAGS  = -g

  LIBS = -lxml2 -lcrypto

  CURR_DIR = `pwd`

  INCLUDES = -I/usr/include/libxml2/ -I$(CURR_DIR)

  # the build target executable:
  TARGET = verifier

  all: $(TARGET)

  $(TARGET): $(TARGET).c
	mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(TARGET).c  nxjson.c $(INCLUDES) $(LIBS) -o $(BIN)/$(TARGET)

  clean:
	rm -rf $(BIN)
