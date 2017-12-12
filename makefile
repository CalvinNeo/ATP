CC = gcc
CXX = g++-7

CFLAGS=-w -Wno-unused-variable -Wno-unused-but-set-variable -DPOSIX -g -O0 -fpermissive -fPIC -std=c++1z $(NO_WARN)
OBJ_EXT=o

SRC_ROOT = ./src
BIN_ROOT = ./bin
OBJ_ROOT = $(BIN_ROOT)/obj

SRCS = $(wildcard $(SRC_ROOT)/*.cpp)
OBJS = $(patsubst $(SRC_ROOT)%, $(OBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))

all: demos lib

demos: demo demo_file demo_poll
demo: recv send 
demo_file: sendfile recvfile 
demo_poll: send_poll recv
	
lib: libatp.so libatp.a

buffer_test: 
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/buffer_test $(SRC_ROOT)/test/buffer_test.cpp -L/usr/lib/

recv: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/recv $(SRC_ROOT)/test/recv.cpp $(OBJS) -L/usr/lib/

send: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/send $(SRC_ROOT)/test/send.cpp $(OBJS) -L/usr/lib/

send_poll: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/send_poll $(SRC_ROOT)/test/send_poll.cpp $(OBJS) -L/usr/lib/

sendfile: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/sendfile $(SRC_ROOT)/test/sendfile.cpp $(OBJS) -L/usr/lib/

recvfile: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/recvfile $(SRC_ROOT)/test/recvfile.cpp $(OBJS) -L/usr/lib/

send_aio: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/send_aio $(SRC_ROOT)/test/send_aio.cpp $(OBJS) -L/usr/lib/ -lrt

libatp.so: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(BIN_ROOT)/libatp.so -shared $(OBJS)

libatp.a: $(OBJS)
	ar rvs $(BIN_ROOT)/libatp.a $(OBJS)

$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(OBJ_ROOT)
	$(CXX) -c $(CFLAGS) $< -o $@

$(OBJ_ROOT):
	mkdir -p $(OBJ_ROOT)

.PHONY : clean
clean:
	rm -rf $(BIN_ROOT)
.PHONY : cleand
cleand:
	rm -r core