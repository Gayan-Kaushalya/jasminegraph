"""Copyright 2023 JasmineGraph Team
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys
import socket
import logging
import subprocess
import time

logging.addLevelName(
    logging.INFO, f'\033[1;32m{logging.getLevelName(logging.INFO)}\033[1;0m')
logging.addLevelName(
    logging.WARNING, f'\033[1;33m{logging.getLevelName(logging.WARNING)}\033[1;0m')
logging.addLevelName(
    logging.ERROR, f'\033[1;31m{logging.getLevelName(logging.ERROR)}\033[1;0m')
logging.addLevelName(
    logging.CRITICAL, f'\033[1;41m{logging.getLevelName(logging.CRITICAL)}\033[1;0m')

logging.getLogger().setLevel(logging.INFO)

HOST = '127.0.0.1'
PORT = 7777  # The port used by the server
UI_PORT = 7776 # The port used by the frontend-ui

LIST = b'lst'
ADGR = b'adgr'
ADGR_CUST = b'adgr-cust'
EMPTY = b'empty'
RMGR = b'rmgr'
VCNT = b'vcnt'
ECNT = b'ecnt'
MERGE = b'merge'
TRAIN = b'train'
TRIAN = b'trian'
PGRNK = b'pgrnk'
SHDN = b'shdn'
SEND = b'send'
DONE = b'done'
ADHDFS = b'adhdfs'
LINE_END = b'\r\n'
IDD = b'idd'
ODD = b'odd'

num_workers = [16, 8, 4, 2]


def stop_and_remove_docker_container():
    """Stops and removes the 'jasminegraph' Docker container."""
    logging.info("Stopping and removing existing 'jasminegraph' container...")
    subprocess.run(['docker', 'kill', 'jasminegraph'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'rm', 'jasminegraph'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("Container stopped and removed.")


def wait_for_port(host, port, timeout=60):
    """Wait until a port starts accepting TCP connections."""
    start_time = time.time()
    while True:
        try:
            with socket.create_connection((host, port), timeout=2):
                logging.info('Port %s is open on %s', port, host)
                return
        except OSError as exc:
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Timed out waiting for port {port} on {host}") from exc
            time.sleep(1)


def expect_response(conn: socket.socket, expected: bytes):
    """Check if the response is equal to the expected response
    Return True if they are equal or False otherwise.
    """
    global passed_all
    buffer = bytearray()
    read = 0
    expected_len = len(expected)
    while read < expected_len:
        received = conn.recv(expected_len - read)
        received_len = len(received)
        if received:
            if received != expected[read:read + received_len]:
                buffer.extend(received)
                data = bytes(buffer)
                logging.warning(
                    'Output mismatch\nexpected : %s\nreceived : %s', expected.decode(),
                    data.decode())
                passed_all = False
                return False
            read += received_len
            buffer.extend(received)
    data = bytes(buffer)
    print(data.decode('utf-8'), end='')
    assert data == expected
    return True


def send_and_expect_response(conn, test_name, send, expected, exit_on_failure=False):
    """Send a message to server and check if the response is equal to the expected response
    Append the test name to failed tests list on failure.
    If exit_on_failure is True, and the response did not match, exit the test script after printing
    the test stats.
    """
    conn.sendall(send + LINE_END)

    if conn._closed:
        logging.error('Connection is closed. Cannot send data.')
        return

    print(send.decode('utf-8'))
    if not expect_response(conn, expected + LINE_END):
        failed_tests.append(test_name)
        if exit_on_failure:
            print()
            logging.fatal('Failed some tests,')
            print(*failed_tests, sep='\n', file=sys.stderr)
            sys.exit(1)


passed_all = True
failed_tests = []


def test(host, port, check_adgr, check_rmgr, workers):
    """Test the JasmineGraph server by sending a series of commands and checking the responses."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        logging.info('Connecting to JasmineGraph with %d workers', workers)

        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            logging.error(f"Connection refused to {host}:{port}. Is the JasmineGraph server running?")
            sys.exit(1)

        if check_adgr:
            print()
            logging.info('Testing lst')
            send_and_expect_response(sock, 'Initial lst', LIST, EMPTY)

            print()
            logging.info(f'Adding graphs with {workers} workers')
            send_and_expect_response(sock, 'adgr', ADGR, SEND, exit_on_failure=True)
            send_and_expect_response(
                sock, 'adgr', f"powergrid|/tmp/jasminegraph/graphs/powergrid.dl".encode("utf-8"), DONE, exit_on_failure=True)


            print()
            logging.info('Testing lst after adgr')
            send_and_expect_response(sock, 'lst after adgr', LIST,
                                    b'|1|powergrid|/tmp/jasminegraph/graphs/powergrid.dl|op|')

        print()
        logging.info('Testing ecnt')
        send_and_expect_response(sock, 'ecnt', ECNT, b'graphid-send')
        send_and_expect_response(sock, 'ecnt', b'1', b'6594')

        print()
        logging.info('Testing vcnt')
        send_and_expect_response(sock, 'vcnt', VCNT, b'graphid-send')
        send_and_expect_response(sock, 'vcnt', b'1', b'4941')

        print()
        logging.info('Testing trian')
        send_and_expect_response(sock, 'trian', TRIAN,
                                 b'graphid-send', exit_on_failure=True)
        send_and_expect_response(
            sock, 'trian', b'1', b'priority(>=1)', exit_on_failure=True)
        send_and_expect_response(sock, 'trian', b'1', b'651')

        print()
        logging.info('Testing pgrnk')
        send_and_expect_response(sock, 'pgrnk', PGRNK,
                                 b'grap', exit_on_failure=True)
        send_and_expect_response(
            sock, 'pgrnk', b'1|0.5|40', b'priority(>=1)', exit_on_failure=True)
        send_and_expect_response(sock, 'pgrnk', b'1',
                                 DONE, exit_on_failure=True)


        if check_rmgr:
            print()
            logging.info('Testing rmgr')
            send_and_expect_response(sock, 'rmgr', RMGR, SEND)
            send_and_expect_response(sock, 'rmgr', b'1', DONE)

            print()
            logging.info('Testing lst after rmgr')
            send_and_expect_response(sock, 'lst after rmgr',
                                    LIST, b'empty')


        ##shutting down workers after testing
        print()
        logging.info('Shutting down JasmineGraph server...')
        sock.sendall(SHDN + LINE_END)
        # Give some time for the server to process the shutdown request
        time.sleep(5)


if __name__ == '__main__':
    number = int(input('Enter the number of workers (2, 4, 8, 16): '))
    if number not in num_workers:
        logging.error('Invalid number of workers. Please choose from 2, 4, 8, or 16.')
        sys.exit(1)

    # Initial cleanup before starting the first container
    stop_and_remove_docker_container()

    docker_command = ['docker', 'run', 
                      '-v', '/var/run/docker.sock:/var/run/docker.sock:rw',
                      '-v', '/root/.ssh:/home/user/.ssh',
                      '-v', '/tmp:/tmp',
                      '-v', '/var/tmp/jasminegraph-localstore:/var/tmp/jasminegraph-localstore',
                      '-v' ,'/var/tmp/jasminegraph-aggregate:/var/tmp/jasminegraph-aggregate',
                      '-v', '/home/user/Documents/jasminegraph/metadb:/home/ubuntu/software/jasminegraph/metadb',
                      '-v' ,'/home/user/Documents/MSc/jasminegraph/performancedb:/home/ubuntu/software/jasminegraph/performancedb',
                      '-p', '7777:7777',
                      '-p', '7778:7778', 'jasminegraph',
                      '--MODE', '1' ,
                      '--MASTERIP', '172.17.0.1',
                      '--WORKERIP' ,'172.17.0.1' ,'--ENABLE_NMON', 'false']

    try:
        current_workers_to_test = number
        # Run the first test case
        logging.info(f"Starting initial test with {current_workers_to_test} workers.")
        process = subprocess.Popen(docker_command + ['--WORKERS', str(current_workers_to_test)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_for_port(HOST, PORT, timeout=60) # Increased timeout for initial boot
        test(HOST, PORT, check_adgr=True, check_rmgr=False, workers=current_workers_to_test)
        # Ensure the container is stopped and removed after each test run
        stop_and_remove_docker_container()

        for x in num_workers:
            if x != number:
                current_workers_to_test = x
                logging.info(f"Starting subsequent test with {current_workers_to_test} workers.")
                stop_and_remove_docker_container() # Ensure clean slate before new run
                process = subprocess.Popen(docker_command + ['--WORKERS', str(current_workers_to_test)],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                wait_for_port(HOST, PORT, timeout=60) # Increased timeout

                if number == 2:
                    if current_workers_to_test in [16, 8]: # Example: check_adgr only for first few
                        test(HOST, PORT, check_adgr=False, check_rmgr=False, workers=current_workers_to_test)
                    else:
                        test(HOST, PORT, check_adgr=False, check_rmgr=True, workers=current_workers_to_test)
                    stop_and_remove_docker_container() # Cleanup after each test run
                else:
                    if number != 2:
                        test(HOST, PORT, check_adgr=True, check_rmgr=False, workers=current_workers_to_test)
                    else:
                        test(HOST, PORT, check_adgr=False, check_rmgr=True, workers=current_workers_to_test)
                    stop_and_remove_docker_container()

    except TimeoutError as e:
        logging.critical(str(e))
        logging.critical("Killing Docker container due to timeout.")
        stop_and_remove_docker_container() # Ensure cleanup on timeout
        sys.exit(1)
    finally:
        if passed_all:
            print()
            logging.info('Passed all tests')
        else:
            print()
            logging.critical('Failed some tests')
            print(*failed_tests, sep='\n', file=sys.stderr)
            sys.exit(1)
