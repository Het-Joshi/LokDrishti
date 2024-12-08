import socket
import threading
import os
import time
import logging
from collections import deque
from pyspark.sql import SparkSession
import re
import psutil  # For CPU and memory usage monitoring
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configurations
HOST = '192.168.1.27'  # Listen on all interfaces
PORT = 9092
LOG_STORAGE_DIR = '/tmp/logs/'  # Directory to temporarily store incoming logs
BUFFER_SIZE = 1024  # Size for buffer to hold log data before processing
THREAT_LOG_FILE = '/tmp/threat_logs.txt'  # File to store detected threats

# Threshold configurations
CPU_USAGE_THRESHOLD = 80  # Percentage
LOG_VOLUME_THRESHOLD = 50  # Number of logs within 5 seconds

# Create directories if they don't exist
os.makedirs(LOG_STORAGE_DIR, exist_ok=True)

# Queue to buffer logs temporarily before processing
log_buffer = deque(maxlen=100)  # Stores last 100 logs temporarily

# Configure logging
#logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')

# Threat patterns (expand as necessary)
THREAT_PATTERNS = [
    r"Failed login attempt",               # Example: Detect failed login attempts
    r"SQL injection detected|DROP TABLE",  # Example: Detect SQL injection attempts
    r"Port scan detected from [\d\.]+",    # Example: Detect port scanning attempts
    r"Unauthorized access attempt",        # Example: Detect unauthorized access attempts
    r"Cross-site scripting|<script>",      # Example: Detect XSS attacks
    r"Brute force attempt",                # Example: Detect brute force attacks
]

def detect_threat(log_message):
    """
    Check if the log message contains any threats.
    
    Parameters:
        log_message (str): The log message to analyze.
        
    Returns:
        tuple: (bool, str) True if a threat is detected, along with the matching pattern.
    """
    for pattern in THREAT_PATTERNS:
        if re.search(pattern, log_message, re.IGNORECASE):
            return True, pattern
    return False, None

def handle_client_connection(client_socket, client_address):
    """Handle the client connection."""
    file_path = os.path.join(LOG_STORAGE_DIR, f"{client_address[0]}_logs.txt")
    with open(file_path, 'a') as log_file:
        logging.info("Connection established with %s", client_address)
        try:
            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                log_message = data.decode('utf-8').strip()  # Decode bytes to string
                #print(Fore.CYAN + f"[LOG RECEIVED] {log_message}")
                #log_file.write(log_message + '\n')
                log_buffer.append(log_message)  # Add the log to the buffer
        except Exception as e:
            print(Fore.RED + f"[ERROR] {client_address}: {e}")
        finally:
            logging.info("Connection closed with %s", client_address)
            client_socket.close()

def monitor_system_metrics():
    """Monitor system metrics like CPU usage and log volume."""
    while True:
        # Check CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        if cpu_usage > CPU_USAGE_THRESHOLD:
            print(Fore.RED + f"[WARNING] High CPU usage detected: {cpu_usage}% (Threshold: {CPU_USAGE_THRESHOLD}%)")
        
        # Check log volume
        if len(log_buffer) > LOG_VOLUME_THRESHOLD:
            print(Fore.RED+ f"[WARNING] High log volume detected: {len(log_buffer)} logs (Threshold: {LOG_VOLUME_THRESHOLD} logs)")
        
        time.sleep(5)  # Monitor every 5 seconds

def process_logs_with_spark():
    """
    Process logs using PySpark at regular intervals, 
    analyze them for threats, and take necessary actions.
    """
    spark = SparkSession.builder.appName("RealTimeLogAnalysis").getOrCreate()

    try:
        while True:
            time.sleep(5)  # Process logs every 5 seconds

            if log_buffer:
                # Create a string from the buffered logs
                log_data = "\n".join(log_buffer)

                if not log_data.strip():
                    logging.info("No valid logs to process.")
                    continue

                print(Fore.GREEN + "[INFO] Processing buffered logs...")
                df = spark.createDataFrame([(log,) for log in log_data.split("\n")], ["log"])

                with open(THREAT_LOG_FILE, 'a') as threat_file:
                    for row in df.collect():
                        log_line = row.log
                        print(Fore.BLUE + log_line)  # Print logs for transparency

                        # Detect threats
                        is_threat, pattern = detect_threat(log_line)
                        if is_threat:
                            threat_message = f"Threat detected: {log_line.strip()} | Pattern: {pattern}"
                            print(Fore.RED + "[THREAT DETECTED] " + threat_message)
                            threat_file.write(threat_message + '\n')

                # Clear buffer after processing
                log_buffer.clear()
    except Exception as e:
        print(Fore.RED + f"[ERROR] Error processing logs: {e}")

def start_server():
    """Start the master server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(Fore.GREEN + f"Master Node listening on {HOST}:{PORT}")
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(
                target=handle_client_connection,
                args=(client_socket, client_address)
            ).start()

if __name__ == "__main__":
    # Start server in a separate thread to listen for client connections
    threading.Thread(target=start_server, daemon=True).start()

    # Start system metrics monitoring in a separate thread
    threading.Thread(target=monitor_system_metrics, daemon=True).start()

    # Start processing the logs with PySpark
    process_logs_with_spark()

