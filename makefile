CC = gcc
CXX = g++

CFLAGS=-w -DPOSIX -g -O0 -fpermissive -fPIC -std=c++1z $(NO_WARN)
OBJ_EXT=o

SRC_ROOT = ./src
BIN_ROOT = ./bin
OBJ_ROOT = $(BIN_ROOT)/obj

SRCS = $(wildcard $(SRC_ROOT)/*.cpp)
OBJS = $(patsubst $(SRC_ROOT)%, $(OBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))

all: demo lib

demo: recv send 
lib: libatp.so libatp.a

buffer_test: 
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/buffer_test $(SRC_ROOT)/test/buffer_test.cpp -L/usr/lib/

recv: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/recv $(SRC_ROOT)/test/recv.cpp $(OBJS) -L/usr/lib/

send: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/send $(SRC_ROOT)/test/send.cpp $(OBJS) -L/usr/lib/

libatp.so: $(OBJS)
	$(CXX) $(CXXFLAGS) -o libatp.so -shared $(OBJS)

libatp.a: $(OBJS)
	ar rvs libatp.a $(OBJS)

$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(OBJ_ROOT)
	$(CXX) -c $(CFLAGS) $< -o $@

$(OBJ_ROOT):
	mkdir -p $(OBJ_ROOT)

.PHONY : clean
clean:
	rm -rf $(BIN_ROOT)