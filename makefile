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

demo: receiver sender 
lib: libatp.so libatp.a

receiver: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/receiver $(SRC_ROOT)/test/receiver.cpp $(OBJS) -L/usr/lib/

sender: $(OBJS)
	$(CXX) $(CFLAGS) -o $(BIN_ROOT)/sender $(SRC_ROOT)/test/sender.cpp $(OBJS) -L/usr/lib/

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