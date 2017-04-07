  # the compiler: gcc for C program
  CC = gcc

  VERIFIER_ROOT=..
  BIN=$(VERIFIER_ROOT)/bin
  OBJ=$(VERIFIER_ROOT)/build
  SAFESTRING=./SafeStringLibrary/
  SAFESTRING_INCLUDE=$(SAFESTRING)/include/
  LIBXML_INCLUDE=/usr/include/libxml2/

  # compiler flags:
  #  -g    adds debugging information to the executable file
  LDFLAGS  := -pie -z noexecstack -z relro -z now
  CFLAGS  = -g -Wformat -Wformat-security -fPIE -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2

  LIBS = -lxml2 -lcrypto -lSafeStringRelease
  #LIBS = -lxml2 -lcrypto

  CURR_DIR = `pwd`

  INCLUDES = -I$(LIBXML_INCLUDE) -I$(CURR_DIR) -I$(SAFESTRING_INCLUDE)

  OBJS= $(OBJ)/verifier.o $(OBJ)/char_converter.o

  # the build target executable:
  TARGET = verifier

  all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -L $(SAFESTRING) $(LIBS) -o $(BIN)/$(TARGET)

$(OBJ)/verifier.o: verifier.c
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) $(CURR_DIR)/verifier.c  $(INCLUDES) -c -o $(OBJ)/verifier.o

$(OBJ)/char_converter.o: char_converter.c char_converter.h
	$(CC) $(CFLAGS) -I $(CURR_DIR)/ -c -o $(OBJ)/char_converter.o $(CURR_DIR)/char_converter.c

  

  clean:
	rm -rf $(BIN)
	rm -rf $(OBJ)
