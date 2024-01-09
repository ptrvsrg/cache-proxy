#!/bin/bash

EXIT_CODE=0

echo "1. Test with many requests"
mkdir -p "test_many_requests"
echo "1. Sending..."
TEST_COUNT=100
for i in $(seq 1 $TEST_COUNT); do \
  wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files" \
  -e use_proxy=on \
  -e http_proxy="localhost:8080" \
  -O "./test_many_requests/$i.html" > /dev/null 2>&1 & \
done
if [[ ! -e "./test_many_requests/correct.html" ]]; then
  wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files" \
    -O "./test_many_requests/correct.html" > /dev/null 2>&1 &
fi
wait
echo "1. Checking..."
SUCCESSFUL_TESTS=0
for i in $(seq 1 $TEST_COUNT); do \
  RESULT=$(diff "./test_many_requests/correct.html" "./test_many_requests/$i.html" > /dev/null 2>&1)
  if [[ "$RESULT" -eq 0 ]]; then \
    echo "1. Test $i.html - SUCCESS"
    ((SUCCESSFUL_TESTS = SUCCESSFUL_TESTS + 1))
  else
    echo "1. Test $i.html - FAIL"
    EXIT_CODE=1
  fi
done
echo "1. Successful tests: $SUCCESSFUL_TESTS/$TEST_COUNT"


echo "2. Test with big request"
mkdir -p "test_big_request"
echo "2. Sending..."
if [[ ! -e "./test_big_request/correct.dat" ]]; then
  wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files/50mb.dat" \
  -O "./test_big_request/correct.dat" > /dev/null 2>&1 &
fi
wget "http://www.ccfit.nsu.ru/~rzheutskiy/test_files/50mb.dat" \
  -e use_proxy=on \
  -e http_proxy="localhost:8080" \
  -O "./test_big_request/50mb.dat"
wait
echo "2. Checking..."
SUCCESSFUL_TESTS=0
RESULT=$(diff "./test_big_request/correct.dat" "./test_big_request/50mb.dat" > /dev/null 2>&1)
  if [[ "$RESULT" -eq 0 ]]; then \
    echo "2. Test 50mb.dat - SUCCESS"
    ((SUCCESSFUL_TESTS = SUCCESSFUL_TESTS + 1))
  else
    echo "2. Test 50mb.dat - FAIL"
    EXIT_CODE=1
  fi
echo "2. Successful tests: $SUCCESSFUL_TESTS/1"

exit $EXIT_CODE