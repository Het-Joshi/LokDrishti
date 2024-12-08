import socket
import time
import subprocess
import logging

# Configurations
MASTER_HOST = '192.168.1.27'  # Replace with your master node's IP
MASTER_PORT = 9092  # Port for communication
LOG_INTERVAL = 3  # Interval to send logs in seconds

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_cpu_utilization():
    """Get CPU utilization using the top command."""
    result = subprocess.run(['top', '-bn1'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    for line in output.split('\n'):
        if "Cpu(s)" in line:
            return line.strip()
    return "CPU utilization not available"

def get_memory_utilization():
    """Get memory utilization using the free command."""
    result = subprocess.run(['free', '-m'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    for line in output.split('\n'):
        if "Mem:" in line:
            return line.strip()
    return "Memory utilization not available"

def get_network_stats():
    """Get network stats using the netstat command."""
    result = subprocess.run(['netstat', '-i'], stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8').strip()

def get_failed_ssh_logins():
    """Get failed SSH login attempts from journalctl."""
    failed_logins = []
    try:
        output = subprocess.check_output("sudo journalctl -u ssh | grep 'Failed'", shell=True).decode('utf-8')
        failed_logins = output.splitlines()  # Keep raw lines as they are
    except subprocess.CalledProcessError as e:
        logging.error("Error fetching SSH logs: %s", e)
    return failed_logins


def collect_system_logs():
    """Collect system logs and return a formatted message."""
    cpu = get_cpu_utilization()
    memory = get_memory_utilization()
    network = get_network_stats()
    failed_logins = get_failed_ssh_logins()

    log_message = f"CPU: {cpu}\nMemory: {memory}\nNetwork:\n{network}\nFailed SSH Logins:\n"
    for login in failed_logins:
        log_message += f"{login}\n" 
    
    return log_message

def send_logs_to_master():
    """Send logs to the master node at regular intervals."""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((MASTER_HOST, MASTER_PORT))
                logging.info("Connected to Master Node at %s:%d", MASTER_HOST, MASTER_PORT)
                while True:
                    log_message = collect_system_logs()
                    s.sendall(log_message.encode('utf-8') + b'\n')
                    time.sleep(LOG_INTERVAL)
        except (socket.error, ConnectionRefusedError) as e:
            logging.error("Connection error: %s. Retrying in %d seconds...", e, LOG_INTERVAL)
            time.sleep(LOG_INTERVAL)

if __name__ == "__main__":
    try:
        send_logs_to_master()
    except KeyboardInterrupt:
        logging.info("Client terminated.")
    except Exception as e:
        logging.error("Unexpected error: %s", e)
