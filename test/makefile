CC = gcc
CXX = g++-7

cov_comp = -fprofile-arcs -ftest-coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW
cov_lnk = -fprofile-arcs -ftest-coverage --coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW

NO_WARN = -w
TRIM_WARN = -Wno-unused-variable -Wno-unused-but-set-variable -Wformat-security
CFLAGS = -DPOSIX -g -fpermissive -std=c++1z 

ifeq ($(MODE), COV)
	# "Coverage mode"
	CFLAGS_COV = $(cov_comp)
	CFLAGS_COV_LNK = $(cov_lnk)
	CFLAGS += -O0
	CFLAGS += $(TRIM_WARN)
else ifeq ($(MODE), DEBUG)
	# "Debug mode"
	CFLAGS += -O0
else
	# "Normal mode"
	CFLAGS_COV = 
	CFLAGS_COV_LNK = 
	CFLAGS += -O2
	CFLAGS += $(NO_WARN)
endif

OBJ_EXT=o

ROOT = ..
SRC_ROOT = .
BIN_ROOT = $(ROOT)/bin
OBJ_ROOT = $(BIN_ROOT)/obj
TEST_ROOT = .

SRCS = $(wildcard $(SRC_ROOT)/*.cpp)
OBJS = $(patsubst $(SRC_ROOT)%, $(OBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))

all: demos
demo_cmd: recv send  packet_sim
demo_file: sendfile recvfile 
demo_poll: sendfile_poll recvfile
demo_multi: multi_recv send
demo_server: recv_server send_server 

demos: demo_cmd demo_file demo_poll demo_multi demo_server buffer_test


# use bash's `&` and wait cause trouble here, refer to earlier commits
run_test:
	cd $(ROOT) && python test/makedata.py
	cd $(ROOT) && python test/run_test.py

run_cov: run_test
	gcov -r -o *.gcno
	gcov -r -o $(OBJ_ROOT)/*.gcno

run_lcov: 
	lcov -c -o ATP.lcov.info -d $(ROOT)
	genhtml ATP.lcov.info -o ATPLCovHTML

run_coveralls_local: run_cov
	coveralls -b $(ROOT) -r $(ROOT) --dryrun --gcov-options '\-r'

run_coveralls: run_cov
	coveralls -b $(ROOT) -r $(ROOT) --gcov-options '\-r'

buffer_test:  
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/buffer_test buffer_test.cpp -L/usr/lib/ $(BIN_ROOT)/libatp.a -I$(ROOT)/src

recv: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recv recv.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

send: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send send.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

sendfile_test: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile_test sendfile_test.cpp $(TEST_UTILS) -I$(ROOT)/src

sendfile_poll: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile_poll sendfile_poll.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

sendfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/sendfile sendfile.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

recvfile: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recvfile recvfile.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

send_aio: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send_aio send_aio.cpp -L/usr/lib/ -lrt -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

packet_sim: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/packet_sim packet_sim.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

multi_recv: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/multi_recv multi_recv.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

recv_server: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/recv_server recv_server.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

send_server: 
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/send_server send_server.cpp -L/usr/lib/ -lpthread $(BIN_ROOT)/libatp.a -I$(ROOT)/src

.PHONY: clean
clean: clean_cov
	rm -rf $(BIN_ROOT)
	rm -rf in.*
	rm -rf out.*
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