import argparse
import logging
import sys
import socket
import random
import time
import os
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.DEBUG,  # Set to INFO or WARNING for less verbose output
                    format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Network Protocol Fuzzer for vulnerability analysis.")

    # Target related arguments
    parser.add_argument("-t", "--target", dest="target_ip", required=True,
                        help="Target IP address or hostname.")
    parser.add_argument("-p", "--port", dest="target_port", type=int, required=True,
                        help="Target port number.")

    # Fuzzing parameters
    parser.add_argument("-P", "--protocol", dest="protocol", default="TCP",
                        choices=["TCP", "UDP"],
                        help="Network protocol to fuzz (TCP or UDP). Default: TCP")
    parser.add_argument("-n", "--num-packets", dest="num_packets", type=int, default=100,
                        help="Number of packets to send. Default: 100")
    parser.add_argument("-s", "--packet-size", dest="packet_size", type=int, default=100,
                        help="Size of each packet in bytes. Default: 100")
    parser.add_argument("-d", "--delay", dest="delay", type=float, default=0.01,
                        help="Delay between sending packets (in seconds). Default: 0.01")

    # Fuzzing techniques
    parser.add_argument("-f", "--fuzz-type", dest="fuzz_type", default="random",
                        choices=["random", "mutate", "overflow"],
                        help="Fuzzing type: random, mutate, or overflow. Default: random")
    parser.add_argument("-m", "--mutation-rate", dest="mutation_rate", type=float, default=0.1,
                        help="Mutation rate for 'mutate' fuzzing (0.0 to 1.0). Default: 0.1")
    parser.add_argument("-o", "--overflow-amount", dest="overflow_amount", type=int, default=1000,
                        help="Overflow amount for 'overflow' fuzzing (in bytes). Default: 1000")
    # Logging and reporting
    parser.add_argument("-l", "--log-file", dest="log_file",
                        help="Path to the log file. If not specified, logs will be printed to the console.")
    parser.add_argument("-r", "--report-file", dest="report_file",
                        help="Path to save the data analysis report (CSV).")

    return parser.parse_args()


def create_socket(protocol):
    """
    Creates a socket based on the specified protocol.

    Args:
        protocol (str): The network protocol to use ("TCP" or "UDP").

    Returns:
        socket.socket: The created socket object.

    Raises:
        ValueError: If an invalid protocol is specified.
        socket.error: If there's an error creating the socket.
    """
    try:
        if protocol == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raise ValueError("Invalid protocol specified. Must be 'TCP' or 'UDP'.")
        return sock
    except socket.error as e:
        logging.error(f"Socket creation failed: {e}")
        raise


def connect_socket(sock, target_ip, target_port, protocol):
    """
    Connects the socket to the target (TCP only).

    Args:
        sock (socket.socket): The socket object.
        target_ip (str): The target IP address.
        target_port (int): The target port.
        protocol (str): The network protocol.

    Raises:
        socket.error: If there's an error connecting the socket.
    """
    if protocol == "TCP":
        try:
            sock.connect((target_ip, target_port))
            logging.info(f"Connected to {target_ip}:{target_port} via TCP.")
        except socket.error as e:
            logging.error(f"Connection failed: {e}")
            raise
    else:
        logging.info(f"Using UDP, no connection needed.  Sending to {target_ip}:{target_port}.")


def generate_random_packet(packet_size):
    """
    Generates a random packet of the specified size.

    Args:
        packet_size (int): The size of the packet in bytes.

    Returns:
        bytes: The generated random packet.
    """
    return os.urandom(packet_size)


def mutate_packet(packet, mutation_rate):
    """
    Mutates a packet by randomly changing bytes based on the mutation rate.

    Args:
        packet (bytes): The packet to mutate.
        mutation_rate (float): The probability of each byte being mutated (0.0 to 1.0).

    Returns:
        bytes: The mutated packet.
    """
    packet_list = list(packet)
    for i in range(len(packet_list)):
        if random.random() < mutation_rate:
            packet_list[i] = random.randint(0, 255)
    return bytes(packet_list)


def overflow_packet(packet, overflow_amount):
    """
    Creates an overflow packet by appending a large number of random bytes to the original packet.

    Args:
        packet (bytes): The original packet.
        overflow_amount (int): The number of bytes to overflow.

    Returns:
        bytes: The overflowed packet.
    """
    overflow_data = os.urandom(overflow_amount)
    return packet + overflow_data


def fuzz(target_ip, target_port, protocol, num_packets, packet_size, delay, fuzz_type, mutation_rate, overflow_amount):
    """
    Fuzzes the target service by sending malformed packets.

    Args:
        target_ip (str): The target IP address.
        target_port (int): The target port.
        protocol (str): The network protocol ("TCP" or "UDP").
        num_packets (int): The number of packets to send.
        packet_size (int): The size of each packet in bytes.
        delay (float): The delay between sending packets (in seconds).
        fuzz_type (str): The fuzzing type ("random", "mutate", or "overflow").
        mutation_rate (float): The mutation rate for "mutate" fuzzing.
        overflow_amount (int): The overflow amount for "overflow" fuzzing.
    """
    try:
        sock = create_socket(protocol)
        connect_socket(sock, target_ip, target_port, protocol)

        packet_data = []  # List to store packet data for analysis
        timestamps = []   # List to store timestamps for each packet

        for i in range(num_packets):
            try:
                # Generate initial packet
                packet = generate_random_packet(packet_size)

                # Apply fuzzing based on selected type
                if fuzz_type == "random":
                    pass  # Already random
                elif fuzz_type == "mutate":
                    packet = mutate_packet(packet, mutation_rate)
                elif fuzz_type == "overflow":
                    packet = overflow_packet(packet, overflow_amount)
                else:
                    logging.error(f"Invalid fuzz_type: {fuzz_type}")
                    return

                # Send the packet
                start_time = time.time()  # Capture timestamp before sending
                sock.sendto(packet, (target_ip, target_port)) if protocol == "UDP" else sock.sendall(packet)
                end_time = time.time()    # Capture timestamp after sending

                # Record data for analysis
                packet_data.append(len(packet))  # Record packet size
                timestamps.append(start_time)     # Record timestamp

                logging.debug(f"Packet {i+1}/{num_packets} sent. Size: {len(packet)} bytes. Fuzz type: {fuzz_type}.")
                time.sleep(delay)

            except socket.error as e:
                logging.error(f"Error sending packet: {e}")
                break  # Stop sending packets if an error occurs

            except Exception as e:
                logging.error(f"An unexpected error occurred during fuzzing: {e}")
                break

    except Exception as e:
        logging.error(f"Fuzzing process failed: {e}")

    finally:
        if protocol == "TCP":  # Only shutdown TCP sockets
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                logging.warning(f"Error shutting down socket: {e}")
        sock.close()
        logging.info("Socket closed.")
        return packet_data, timestamps


def analyze_and_report(packet_data, timestamps, report_file):
    """
    Analyzes the collected packet data and generates a report.

    Args:
        packet_data (list): A list of packet sizes.
        timestamps (list): A list of timestamps when packets were sent.
        report_file (str): The path to save the report file (CSV).
    """
    if not packet_data:
        logging.warning("No packet data to analyze.")
        return

    try:
        # Create a Pandas DataFrame
        df = pd.DataFrame({'Timestamp': timestamps, 'PacketSize': packet_data})

        # Basic statistics
        mean_size = df['PacketSize'].mean()
        max_size = df['PacketSize'].max()
        min_size = df['PacketSize'].min()

        # Log basic stats
        logging.info(f"Mean packet size: {mean_size:.2f} bytes")
        logging.info(f"Max packet size: {max_size} bytes")
        logging.info(f"Min packet size: {min_size} bytes")

        # Save the DataFrame to a CSV file
        if report_file:
            df.to_csv(report_file, index=False)
            logging.info(f"Report saved to: {report_file}")
        else:
            logging.info("No report file specified.  Analysis complete but report not saved.")

    except Exception as e:
        logging.error(f"Error analyzing data or generating report: {e}")


def main():
    """
    Main function to parse arguments, run the fuzzer, and generate a report.
    """
    args = setup_argparse()

    # Configure logging to file, if specified
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.DEBUG)  # Or INFO, WARNING, etc.
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(file_handler)  # Add to root logger

    logging.info("Starting network protocol fuzzer...")

    # Input validation
    if not 0 < args.packet_size <= 65535:
        logging.error("Invalid packet size. Must be between 1 and 65535 bytes.")
        sys.exit(1)

    if not 0 <= args.mutation_rate <= 1:
        logging.error("Invalid mutation rate. Must be between 0.0 and 1.0.")
        sys.exit(1)

    if args.num_packets <= 0:
        logging.error("Number of packets must be greater than 0.")
        sys.exit(1)

    if args.delay < 0:
        logging.error("Delay must be a non-negative number.")
        sys.exit(1)

    try:
        # Call the fuzzing function
        packet_data, timestamps = fuzz(args.target_ip, args.target_port, args.protocol, args.num_packets,
                                       args.packet_size, args.delay, args.fuzz_type, args.mutation_rate,
                                       args.overflow_amount)
        # Analyze and report the data
        analyze_and_report(packet_data, timestamps, args.report_file)

    except Exception as e:
        logging.critical(f"Fuzzer execution failed: {e}")
        sys.exit(1)

    logging.info("Fuzzing complete.")


if __name__ == "__main__":
    main()


"""
Usage Examples:

1.  Basic fuzzing of a TCP service on port 8080 with random packets:

    python main.py -t 127.0.0.1 -p 8080 -n 100 -s 500 -P TCP

2.  Fuzzing a UDP service with mutated packets and a report file:

    python main.py -t 192.168.1.100 -p 53 -n 200 -s 256 -P UDP -f mutate -m 0.2 -r udp_fuzz_report.csv

3.  Fuzzing with overflow packets and logging to a file:

    python main.py -t example.com -p 21 -n 50 -s 100 -f overflow -o 2000 -l fuzz.log

4.  Displaying help:

    python main.py -h

5. Running with a different delay and smaller packets

    python main.py -t 127.0.0.1 -p 8000 -n 50 -s 64 -d 0.05 -P TCP

"""