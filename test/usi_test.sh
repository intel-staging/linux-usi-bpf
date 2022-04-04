#!/bin/sh

if [ ! -x hid_usi_server ] || [ ! -x hid_usi_client ] ; then
  echo "hid_usi_* binaries not found in current directory."
  exit 1
fi

mkdir -p /var/tests

LOG=/var/tests/usi.log

echo "=========================" >> $LOG
date >> $LOG
echo "Starting tests." >> $LOG

run_test()
{
  MODE=$1
  ID=$2
  ARGS=$3
  EXPECTED=$4
  BG=$5

  # Expected return value for test binary
  if [ "$EXPECTED" = "" ] ; then
    EXPECTED=0
  fi

  # Test binary setup. 'prof' is the log file to use for clang test coverage.
  if [ "$1" = "server" ] ; then
    prof=/var/tests/hid_usi_server${ID}.profraw
    prog=./hid_usi_server
  else
    prof=/var/tests/hid_usi_client${ID}.profraw
    prog=./hid_usi_client
  fi
  echo "Running $MODE test $ID"
  echo "----------------------" >> $LOG
  echo "Running $MODE test $ID" >> $LOG
  if [ "$BG" != "" ] ; then
    LLVM_PROFILE_FILE=$prof $prog $ARGS >> $LOG 2>&1 &
  else
    LLVM_PROFILE_FILE=$prof $prog $ARGS >> $LOG 2>&1
  fi

  RET=$?

  # Capture started process id for background mode
  if [ "$BG" != "" ] ; then
    if [ "$MODE" = "server" ] ; then
      server_pid=$!
    else
      client_pid=$!
    fi
  fi

  # Verify result
  if [ "$EXPECTED" != "$RET" ] ; then
    echo "ERROR: $MODE test $ID returned $RET, expected $EXPECTED!"
    exit 1
  fi
}

# Run a simple test with DBUS session bus
echo "Running session bus test." >> $LOG
dbus-launch > /tmp/usi-dbus-session
export $(cat /tmp/usi-dbus-session)

run_test "server" 1 "--session 0" 0 1

sleep 1

run_test "client" 1 "--session --dump" 0

echo "Terminating server $server_pid" >> $LOG
kill -INT $server_pid
echo "Terminating dbus session." >> $LOG
kill -INT $DBUS_SESSION_BUS_PID

# Server tests
run_test "server" 2 "--help" 1
run_test "server" 3 "" 1
run_test "server" 4 "11" 1
run_test "server" 5 "foo" 1

# Run server in debug mode to cover debug prints
run_test "server" 6 "--debug 0" 0 1
sleep 1

# Run 'Get' methods for couple of variables with a python script
# Client uses cache and does not cover these
./pen.py -g -c >> $LOG
./pen.py -v >> $LOG

# Query / set an invalid parameter
./pen.py -g -u "CustomVar" >> $LOG
./pen.py -u "CustomVar" 3 >> $LOG

# Client tests
run_test "client" 2 "--help" 1
run_test "client" 3 "" 1
run_test "client" 4 "--dump" 0
run_test "client" 5 "--color" 0
run_test "client" 6 "--width" 0
run_test "client" 7 "--style" 0
run_test "client" 8 "--color 0" 1
echo "Please hold a pen on screen."

run_test "client" 9 "--monitor --exit" 0

echo "Pen detected!"

run_test "client" 10 "--color 2" 0
run_test "client" 11 "--width 3" 0
run_test "client" 12 "--style 4" 0
run_test "client" 13 "--color 99999" 1
run_test "client" 14 "--color 12345678901234567890" 1
run_test "client" 15 "--color 1 2 3" 1

# Read back set values
col=$(./hid_usi_client --color | grep ":" | cut -d ":" -f 2 | cut -c 2-)
wid=$(./hid_usi_client --width | grep ":" | cut -d ":" -f 2 | cut -c 2-)
sty=$(./hid_usi_client --style | grep ":" | cut -d ":" -f 2 | cut -c 2-)

if [ "$col" != "2" ] || [ "$wid" != "3" ] || [ "$sty" != "4" ] ; then
  echo "Bad values [$col,$wid,$sty], expected [2,3,4]"
  echo "Stopping server $server_pid..."
  kill -INT $server_pid
  exit 1
fi

echo "Stopping server $server_pid..."
kill -INT $server_pid

echo "All done!"

exit 0
