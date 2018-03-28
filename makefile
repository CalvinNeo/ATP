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

cov_comp = -fprofile-arcs -ftest-coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW
cov_lnk = -fprofile-arcs -ftest-coverage --coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW

demo: recv send 
demo_file: sendfile recvfile 
demo_poll: sendfile_poll recvfile
demo_multi: multi_recv send

demos: CFLAGS_COV = 
demos: CFLAGS_COV_LNK = 
demos: lib demo demo_file demo_poll demo_multi

demos_cov: CFLAGS_COV = $(cov_comp)
demos_cov: CFLAGS_COV_LNK = $(cov_lnk)
demos_cov: lib demo_file packet_sim demo_poll demo demo_multi

demo_multi_cov: CFLAGS_COV = $(cov_comp)
demo_multi_cov: CFLAGS_COV_LNK = $(cov_lnk)
demo_multi_cov: multi_recv send

demo_cov: CFLAGS_COV = $(cov_comp)
demo_cov: CFLAGS_COV_LNK = $(cov_lnk)
demo_cov: recv send

# use bash's `&` and wait cause trouble here, refer to earlier commits
run_test:
	python $(SRC_ROOT)/test/makedata.py
	python $(SRC_ROOT)/test/run_test.py

run_cov: run_test
	gcov -r -o *.gcno
	gcov -r -o $(OBJ_ROOT)/*.gcno

run_lcov: 
	lcov -c -o ATP.lcov.info -d ./
	# lcov -c -o ATP.lcov.info -d $(OBJ_ROOT)/
	genhtml ATP.lcov.info -o ATPLCovHTML

run_coveralls_local: run_cov
	coveralls -b ./ -r ./ --dryrun --gcov-options '\-r'

run_coveralls: run_cov
	coveralls -b ./ -r ./ --gcov-options '\-r'

buffer_test:  
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/buffer_test $(SRC_ROOT)/test/buffer_test.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a

recv: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recv $(SRC_ROOT)/test/recv.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

send: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send $(SRC_ROOT)/test/send.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

sendfile_test: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile_test $(SRC_ROOT)/test/sendfile_test.cpp $(TEST_UTILS)

sendfile_poll: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile_poll $(SRC_ROOT)/test/sendfile_poll.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

sendfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile $(SRC_ROOT)/test/sendfile.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

recvfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recvfile $(SRC_ROOT)/test/recvfile.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

send_aio: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send_aio $(SRC_ROOT)/test/send_aio.cpp -L/usr/lib/ -lrt -lpthread $(BIN_ROOT)/libatp.a

packet_sim: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/packet_sim $(SRC_ROOT)/test/packet_sim.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a

multi_recv: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/multi_recv $(SRC_ROOT)/test/multi_recv.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a


$(BIN_ROOT)/libatp.so: $(OBJS)
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/libatp.so -shared $(OBJS)

$(BIN_ROOT)/libatp.a: $(OBJS)
	ar rvs $(BIN_ROOT)/libatp.a $(OBJS)


$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(OBJ_ROOT)
	$(CXX) -c $(CFLAGS) $(CFLAGS_COV) $< -o $@

$(OBJ_ROOT):
	mkdir -p $(OBJ_ROOT)

buffer: $(OBJ_ROOT)
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/buffer_test $(SRC_ROOT)/test/buffer_test.cpp

.PHONY: clean
clean: clean_cov
	rm -rf $(BIN_ROOT)
.PHONY: clc
clc:
	rm -f core
	rm -f s*.log
	rm -f r*.log
.PHONY: clean_cov
clean_cov:
	find ./ -name "*.info" -delete
	find ./ -name "*.gcov" -delete
	find ./ -name "*.gcda" -delete
	find ./ -name "*.gcno" -delete
	rm -rf ./ATPLCovHTML
	rm -f *.log
.PHONY: kill
kill:
	ps aux | grep -e send | grep -v grep | awk '{print $$2}' | xargs -i kill {}
	ps aux | grep -e recv | grep -v grep | awk '{print $$2}' | xargs -i kill {}