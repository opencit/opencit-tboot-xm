TPMEXT_ROOT=..
BIN=        $(TPMEXT_ROOT)/bin/debug
#BIN=        $(TPMEXT_ROOT)/bin/release

S=          .
TRS=	    .
T=	    .
DEBUG_CFLAGS     := -Wall  -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall  -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall  -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX  -D TEST -D TIXML_USE_STL -D __FLUSHIO__ -D RPMMIO $(DEBUG_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)
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

