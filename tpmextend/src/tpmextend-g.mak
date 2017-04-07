TPMEXT_ROOT=..
ifeq ($(debug),1)
        DEBUG_CFLAGS     := -Wall  -Wno-format -g -DDEBUG
else
        DEBUG_CFLAGS     := -Wall -Wno-unknown-pragmas -Wno-format -O3 -Wformat -Wformat-security
endif

BIN=        $(TPMEXT_ROOT)/bin/debug
#BIN=        $(TPMEXT_ROOT)/bin/release
S=          .
TRS=	    .
T=	    .

O1RELEASE_CFLAGS   := -Wall  -Wno-unknown-pragmas -Wno-format -O1
RELEASE_LDFLAGS  := -pie -z noexecstack -z relro -z now
LDFLAGS          := $(RELEASE_LDFLAGS)
CFLAGS=     -fPIE -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2 -D LINUX  -D TEST -D TIXML_USE_STL -D __FLUSHIO__ -D RPMMIO $(DEBUG_CFLAGS)
O1CFLAGS=    -D LINUX -D TEST -D TIXML_USE_STL -D __FLUSHIO__ $(O1RELEASE_CFLAGS)

CC=         g++
LINK=       g++


all: $(BIN)/tpmextend

$(BIN)/tpmextend: 
	mkdir -p $(BIN)
	@echo "tpmextend"
	$(LINK) $(CFLAGS) $(TRS)/tpmextend.cpp -I. -o $(BIN)/tpmextend $(LDFLAGS)  

clean:
	rm -rf $(BIN)/tpmextend

