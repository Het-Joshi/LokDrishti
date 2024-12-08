# LokDrishti

### Installation

```shell
git clone https://github.com/Het-Joshi/LokDrishti.git
cd LokDrishti
```

### **newAnalysis.py** - Real-Time Log Analysis and Threat Detection

#### Overview
The `newAnalysis.py` script is a server-side component designed to receive log data from client nodes, process the data, detect potential threats, and monitor system metrics such as CPU usage, memory utilization, and log volume. It utilizes PySpark for real-time log processing and displays threat alerts with color-coded messages in the terminal.

---

#### **Features**
- Listens for incoming log messages from clients using a TCP socket.
- Analyzes logs in real time with PySpark for detecting predefined security threats.
- Monitors system metrics (CPU, memory, log volume) and generates warnings if thresholds are exceeded.
- Threats are detected based on regular expressions and stored in a log file.
- Provides color-coded console output using `colorama` for better visibility of log statuses and warnings.

---

#### **Prerequisites**
1. **Python 3.x** - Ensure that Python is installed on the machine.
2. **Required Libraries**:
   Install the required Python libraries using the following command:
   ```bash
   pip install pyspark psutil colorama
   ```

3. **System Configuration**:
   - Ensure the host IP (`HOST`) and port (`PORT`) are configured correctly for your environment.
   - Verify that the directory for storing logs (`/tmp/logs/`) exists or is configured to a valid path.

4. **Spark**:
   - Install Apache Spark if it is not already installed for PySpark usage.

---

#### **How to Run the Script**
1. **Start the Server**:
   - To run the server, execute the following command in the terminal:
     ```bash
     python newAnalysis.py
     ```
   - This will start the server and begin listening for incoming client connections on the specified `HOST` and `PORT`.

2. **Connect Clients**:
   - Clients (such as the `reporter.py` script) will send log data to the master server at the defined IP and port.

3. **Monitor Logs**:
   - Once the server is running, logs will be received and analyzed for potential security threats.
   - Alerts and system status are displayed in the terminal with color-coded messages for quick identification.

4. **Stop the Script**:
   - Use `CTRL+C` to stop the script and terminate the server.

---

#### **Customization**
- **Threat Detection Patterns**:
   Modify the `THREAT_PATTERNS` list to include additional patterns that you want to monitor.
   
- **Threshold Configuration**:
   You can adjust the thresholds for `CPU_USAGE_THRESHOLD` and `LOG_VOLUME_THRESHOLD` to suit your environment's needs.

- **Log Storage**:
   Change the path of the log storage directory and threat log file by modifying `LOG_STORAGE_DIR` and `THREAT_LOG_FILE`.

---

#### **Additional Notes**
- Ensure the system has sufficient resources for running PySpark, especially if processing large logs.
- If running the script in a production environment, consider using secure communication channels like TLS/SSL for client-server communication.
  
---

### **reporter.py** - Client Log Reporting and Monitoring

#### Overview
The `reporter.py` script collects system information such as CPU usage, memory utilization, network statistics, and failed SSH login attempts. It then sends this data periodically to a master server running the `newAnalysis.py` script for analysis and threat detection.

---

#### **Features**
- Gathers system metrics including CPU usage, memory status, network stats, and failed SSH login attempts.
- Sends collected data to a master server at regular intervals for log analysis.
- Utilizes system commands like `top`, `free`, and `netstat` to gather information.
- Handles potential connection errors by retrying automatically.

---

#### **Prerequisites**
1. **Python 3.x** - Make sure Python is installed.
2. **Required Libraries**:
   Install the necessary libraries using:
   ```bash
   pip install subprocess logging
   ```
   
3. **System Configuration**:
   - Update the `MASTER_HOST` and `MASTER_PORT` variables to match the IP and port of the master server running `newAnalysis.py`.

---

#### **How to Run the Script**
1. **Start the Client**:
   - To start the client, run the following command:
     ```bash
     python reporter.py
     ```

2. **Send Logs**:
   - The client will begin collecting system logs and send them to the master server at the defined intervals (`LOG_INTERVAL` in seconds).

3. **Monitor the Master**:
   - As the client sends logs, the master server will process the data for threats and display warnings based on detected patterns.

4. **Stop the Script**:
   - Use `CTRL+C` to terminate the script.

---

#### **Customization**
- **Log Collection Interval**:
   You can adjust the interval between log submissions by changing the `LOG_INTERVAL` parameter.
   
- **Log Content**:
   Modify the log collection functions (`get_cpu_utilization`, `get_memory_utilization`, etc.) if additional or different system metrics are required.

---

#### **Additional Notes**
- The script relies on the `top`, `free`, and `netstat` system commands. Ensure these commands are available and accessible on the system where the script is running.
- For production use, consider securing the connection between the client and server (e.g., using SSL/TLS).
