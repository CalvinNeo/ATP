CC = gcc
CXX = g++-7

CFLAGS=-w -Wno-unused-variable -Wno-unused-but-set-variable -DPOSIX -g -O0 -fpermissive -fPIC -std=c++1z $(NO_WARN)
OBJ_EXT=o

SRC_ROOT = ./src
BIN_ROOT = ./bin
OBJ_ROOT = $(BIN_ROOT)/obj

SRCS = $(wildcard $(SRC_ROOT)/*.cpp)
OBJS = $(patsubst $(SRC_ROOT)%, $(OBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))


lib: $(BIN_ROOT)/libatp.so $(BIN_ROOT)/libatp.a

all: demos

demo: recv send 
demo_file: sendfile recvfile 
demo_poll: send_poll recv

demos: CFLAGS_COV = 
demos: CFLAGS_COV_LNK = 
demos: lib demo demo_file demo_poll

demos_cov: CFLAGS_COV = -fprofile-arcs -ftest-coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW
demos_cov: CFLAGS_COV_LNK = -fprofile-arcs -ftest-coverage --coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW
demos_cov: lib demo_file

# use bash's `&` and wait cause trouble here, refer to earlier commits
run_test:
	python $(SRC_ROOT)/test/makedata.py
	python $(SRC_ROOT)/test/run_test.py

run_cov: run_test
	gcov -r -o *.gcno
	gcov -r -o $(OBJ_ROOT)/*.gcno

run_lcov: 
	lcov -c -o ATP.lcov.info -d $(OBJ_ROOT)/
	genhtml ATP.lcov.info -o ATPLCovHTML

run_coveralls_local: run_cov
	coveralls -b ./ -r ./ --dryrun --gcov-options '\-r'

run_coveralls: run_cov
	coveralls -b ./ -r ./ --gcov-options '\-r'

buffer_test:  
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/buffer_test $(SRC_ROOT)/test/buffer_test.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

recv: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recv $(SRC_ROOT)/test/recv.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

send: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send $(SRC_ROOT)/test/send.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

send_poll: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send_poll $(SRC_ROOT)/test/send_poll.cpp $(OBJS) -L/usr/lib/ $(BIN_ROOT)/libatp.a

sendfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile $(SRC_ROOT)/test/sendfile.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

recvfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recvfile $(SRC_ROOT)/test/recvfile.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

send_aio: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send_aio $(SRC_ROOT)/test/send_aio.cpp -L/usr/lib/ -lrt $(BIN_ROOT)/libatp.a

packet_sim: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/packet_sim $(SRC_ROOT)/test/packet_sim.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

$(BIN_ROOT)/libatp.so: $(OBJS)
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/libatp.so -shared $(OBJS)

$(BIN_ROOT)/libatp.a: $(OBJS)
	ar rvs $(BIN_ROOT)/libatp.a $(OBJS)


$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(OBJ_ROOT)
	$(CXX) -c $(CFLAGS) $(CFLAGS_COV) $< -o $@

$(OBJ_ROOT):
	mkdir -p $(OBJ_ROOT)

.PHONY: clean
clean: clean_cov
	rm -rf $(BIN_ROOT)
.PHONY: cleand
cleand:
	rm -f core
.PHONY: clean_cov
clean_cov:
	find ./ -name "*.info" -delete
	find ./ -name "*.gcov" -delete
	find ./ -name "*.gcda" -delete
	find ./ -name "*.gcno" -delete
	rm -rf ./ATPLCovHTML
	rm -f *.log