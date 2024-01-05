#!/bin/bash

echo "1. Test with many requests"
mkdir -p "test_many_requests"
TEST_COUNT=100
for i in $(seq 1 $TEST_COUNT); do \
  wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files" \
  -e use_proxy=on \
  -e http_proxy="localhost:8080" \
  -O "./test_many_requests/$i.html" > /dev/null 2>&1 & \
done
wait
echo "1. Checking"
wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files" \
  -O "./test_many_requests/correct.html" > /dev/null 2>&1
SUCCESSFUL_TESTS=0
for i in $(seq 1 $TEST_COUNT); do \
  diff "./test_many_requests/correct.html" "./test_many_requests/$i.html" > /dev/null 2>&1 && \
    echo "1. Test $i.html - SUCCESS" && \
    ((SUCCESSFUL_TESTS = SUCCESSFUL_TESTS + 1)) || \
    echo "1. Test $i.html - FAIL"
done
echo "1. Successful tests: $SUCCESSFUL_TESTS/$TEST_COUNT"

echo "2. Test with big request"
mkdir -p "test_big_request"
wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files/50mb.dat" \
  -e use_proxy=on \
  -e http_proxy="localhost:8080" \
  -O "./test_big_request/50mb.dat" > /dev/null 2>&1 &
wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files/50mb.dat" \
  -O "./test_big_request/correct.dat" > /dev/null 2>&1 &
wait
echo "2. Checking"
SUCCESSFUL_TESTS=0
diff "./test_big_request/correct.dat" "./test_big_request/50mb.dat" > /dev/null 2>&1 && \
  echo "2. Test 50mb.dat - SUCCESS" && \
  ((SUCCESSFUL_TESTS = SUCCESSFUL_TESTS + 1)) || \
  echo "2. Test 50mb.dat - FAIL"
echo "2. Successful tests: $SUCCESSFUL_TESTS/1"