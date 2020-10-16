CC = gcc
CXX = g++-7

cov_comp = -fprofile-arcs -ftest-coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW
cov_lnk = -fprofile-arcs -ftest-coverage --coverage -fno-inline -DATP_LOG_AT_NOTE -DATP_LOG_AT_DEBUG -DATP_LOG_UDP -DATP_DEBUG_TEST_OVERFLOW

NO_WARN = -w
TRIM_WARN = -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format-security -Wno-format
CFLAGS = -DPOSIX -g -fpermissive -std=c++1z -DATP_LOG_AT_NOTE

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

ROOT = .
# Important not to include ".", or gcov -r will fail with some files
SRC_ROOT = src
BIN_ROOT = bin
OBJ_ROOT = $(BIN_ROOT)/obj
DYOBJ_ROOT = $(BIN_ROOT)/dyobj
TEST_ROOT = test

SRCS = $(wildcard $(SRC_ROOT)/*.cpp)
OBJS = $(patsubst $(SRC_ROOT)%, $(OBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))
DYOBJS = $(patsubst $(SRC_ROOT)%, $(DYOBJ_ROOT)%, $(patsubst %cpp, %o, $(SRCS)))

all: lib demos

slib: $(BIN_ROOT)/libatp.a

dylib: $(BIN_ROOT)/libatp.so

lib: slib dylib

demos: slib
	cd $(TEST_ROOT) && make demos MODE=$(MODE)

test: FORCE $(OBJ_ROOT) $(DYOBJ_ROOT)
	cd $(TEST_ROOT) && make $(TARGET) MODE=$(MODE)

run_test:
	python $(TEST_ROOT)/makedata.py
	python $(TEST_ROOT)/run_test.py

run_cov: run_test
	gcov -r -o $(TEST_ROOT)/*.gcno
	gcov -r -o $(OBJ_ROOT)/*.gcno

run_lcov: 
	lcov -c -o ATP.lcov.info -d $(ROOT)
	genhtml ATP.lcov.info -o ATPLCovHTML

run_coveralls_local: run_cov
	cp -a $(SRC_ROOT) $(OBJ_ROOT)
	coveralls --dryrun --gcov-options '\-r' -i src
	# coveralls -b $(SRC_ROOT) -r $(SRC_ROOT) --dryrun --gcov-options '\-r'
	# coveralls -b $(TEST_ROOT) -r $(TEST_ROOT) -n --dryrun --gcov-options '\-r'

run_coveralls: run_cov
	coveralls --gcov-options '\-r' -i src
	# coveralls -b $(TEST_ROOT) -r $(TEST_ROOT) -n --gcov-options '\-r'
	# coveralls -b $(TEST_ROOT) -r $(TEST_ROOT) -n --gcov-options '\-r'

$(BIN_ROOT)/libatp.so: $(DYOBJS)
	$(CXX) $(CFLAGS) $(CFLAGS_COV_LNK) -o $(BIN_ROOT)/libatp.so -shared $(DYOBJS)

$(BIN_ROOT)/libatp.a: $(OBJS)
	ar rvs $(BIN_ROOT)/libatp.a $(OBJS)

$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(OBJ_ROOT)
	$(CXX) -c $(CFLAGS) $(CFLAGS_COV) $< -o $@

$(DYOBJ_ROOT)/%.o: $(SRC_ROOT)/%.cpp $(DYOBJ_ROOT)
	$(CXX) -c $(CFLAGS) -fPIC $(CFLAGS_COV) $< -o $@

$(OBJ_ROOT):
	mkdir -p $(OBJ_ROOT)
$(DYOBJ_ROOT):
	mkdir -p $(DYOBJ_ROOT)

.PHONY: clean
clean: clean_cov
	rm -rf $(BIN_ROOT)
	cd $(TEST_ROOT) && make clean
.PHONY: clc
clc:
	rm -f core
	rm -f s*.log
	rm -f r*.log
	rm vgcore.*
	cd $(TEST_ROOT) && make clc
.PHONY: clean_cov
clean_cov:
	find ./ -name "*.info" -delete
	find ./ -name "*.gcov" -delete
	find ./ -name "*.gcda" -delete
	find ./ -name "*.gcno" -delete
	rm -rf ./ATPLCovHTML
	rm -f *.log
	cd $(TEST_ROOT) && make clean_cov
.PHONY: kill
kill:
	ps aux | grep -e send | grep -v grep | awk '{print $$2}' | xargs -i kill {}
	ps aux | grep -e recv | grep -v grep | awk '{print $$2}' | xargs -i kill {}
FORCE: 