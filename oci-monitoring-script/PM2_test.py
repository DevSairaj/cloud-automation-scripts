import subprocess
import logging
from dotenv import load_dotenv
import oci
import os
import sys
import ast
from prometheus_client import start_http_server, Gauge
import re

# Load environment variables from a .env file
load_dotenv()

# Set up logging with timestamp and log level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class TestPM2:
    """Class to handle OCI monitoring, metrics collection, and alerting."""

    def __init__(self):
        """Function to initialize the Monitoring class with environment variables and OCI clients."""
        try:
            self.instances = ast.literal_eval(os.getenv("instances"))
            self.db_id = os.getenv('db_id')
            self.load_balancer_id = os.getenv('load_balancer_id')
            self.user = os.getenv('user')
            self.fingerprint = os.getenv('fingerprint')
            self.key_file = os.getenv('key_file')
            self.tenancy = os.getenv('tenancy')
            self.region = os.getenv('region')
            self.receiver_email_list = ast.literal_eval(os.getenv("receiver_email_list"))
            self.cpu_utilization_limit = int(os.getenv('cpu_utilization_limit'))
            self.memory_utilization_limit = int(os.getenv('memory_utilization_limit'))

            # Get DB connection credentials
            self.db_dsn2 = os.getenv('DB_DSN2')
            self.db_port2 = os.getenv('DB_PORT2')
            self.db_service_name2 = os.getenv('DB_SERVICE_NAME2')
            self.db_user2 = os.getenv('DB_USER2')
            self.db_password2 = os.getenv('DB_PASSWORD2')
                
            # # Get DB connection credentials
            # self.db_dsn = os.getenv('db_dsn')
            # self.db_port = os.getenv('db_port')
            # self.db_service_name = os.getenv('db_service_name')
            # self.db_user = os.getenv('db_user')
            # self.db_password = os.getenv('db_password')

            # Validate and initialize OCI clients
            self.config = {
                "user": self.user,
                "fingerprint": self.fingerprint,
                "key_file": self.key_file,
                "tenancy": self.tenancy,
                "region": self.region
            }
            oci.config.validate_config(self.config)
            self.monitoring_client = oci.monitoring.MonitoringClient(self.config)
            self.load_balancer_client = oci.load_balancer.LoadBalancerClient(self.config)
            self.compute_client = oci.core.ComputeClient(self.config)
            self.database_client = oci.database.DatabaseClient(self.config)
            
            # Initialize Prometheus metrics
            self.metrics = {
                'cpu_utilization': Gauge('oci_instance_cpu_utilization', 'CPU Utilization of OCI instance', ['instance_name', 'instance_id']),
                'memory_utilization': Gauge('oci_instance_memory_utilization', 'Memory Utilization of OCI instance', ['instance_name', 'instance_id']),
                'disk_read_io': Gauge('oci_instance_disk_read_io', 'Disk Read I/O of the OCI instance', ['instance_name', 'instance_id']),
                'disk_write_io': Gauge('oci_instance_disk_write_io', 'Disk Write I/O of the OCI instance', ['instance_name', 'instance_id']),
                'network_received_io': Gauge('oci_instance_network_received_io', 'Network Received I/O of the OCI instance', ['instance_name', 'instance_id']),
                'network_transmitted_io': Gauge('oci_instance_network_transmitted_io', 'Network Transmitted I/O of the OCI instance', ['instance_name', 'instance_id']),
                'lb_health': Gauge('oci_load_balancer_health', 'Health status of OCI Load Balancer', ['load_balancer_name', 'load_balancer_id']),
                'backend_set_health': Gauge('oci_backend_set_health', 'Health status of OCI Load Balancer Backend Set', ['load_balancer_name', 'load_balancer_id', 'backend_set_name']),
                'instance_status': Gauge('oci_instance_status', 'Status of OCI instance', ['instance_name', 'instance_id']),
                'db_cpu_utilization': Gauge('oci_db_cpu_utilization', 'CPU Utilization of OCI Database', ['db_id']),
                'db_storage_utilization': Gauge('oci_db_storage_utilization', 'Storage Utilization of OCI Database', ['db_id']),
                # 'db_password_expiry_date': Gauge('oci_db_password_expiry_date', 'Days until OCI Database password expires', ['db_id'])
                'latest_patch_version': Gauge('oci_db_latest_patch_version', 'Latest Patch Version of OCI Database', ['version'])
            }

            # Initialize SMTP configurations
            self.smtp_config = {
                'sender_email_key': os.getenv('sender_email_key').encode(),
                'sender_email_encrypted_string': os.getenv('sender_email_encrypted_string').encode(),
                'smtp_server_key': os.getenv('smtp_server_key').encode(),
                'smtp_server_encrypted_string': os.getenv('smtp_server_encrypted_string').encode(),
                'smtp_password_key': os.getenv('smtp_password_key').encode(),
                'smtp_password_encrypted_string': os.getenv('smtp_password_encrypted_string').encode(),
                'smtp_username_key': os.getenv('smtp_username_key').encode(),
                'smtp_username_encrypted_string': os.getenv('smtp_username_encrypted_string').encode(),
                'smtp_port': int(os.getenv('smtp_port'))
            }

            # Initialize alert status and timestamps
            self.cpu_alert_sent = {}
            self.memory_alert_sent = {}
            self.db_cpu_alert_sent = {'alert': None, 'resolve': None}
            self.db_storage_alert_sent = {'alert': None, 'resolve': None}
            self.lb_health_alert_sent = {'alert': None, 'resolve': None}
            self.backend_set_health_alert_sent = {}

            # self.password_expiry_warning_days = 7
            # self.password_expiry_alert_sent = None

            self.alert_sent_timestamps = {
                'cpu_utilization': {},
                'memory_utilization': {},
                'db_cpu_utilization': {'alert': None, 'resolve': None},
                'db_storage_utilization': {'alert': None, 'resolve': None},
                'lb_health': {'alert': None, 'resolve': None},
                'backend_set_health': {}
            }

        except Exception as e:
            logger.error(f"Initialization error: {e}")
            self._log_exception()
            raise

    def _log_exception(self):
        """Utility function to log the exception details including type, file, and line number."""
        exc_type, exc_obj, exc_tb = sys.exc_info()
        if exc_type:
            fname = os.path.basename(exc_tb.tb_frame.f_code.co_filename)
            lineno = exc_tb.tb_lineno
            logger.error(f"Exception type: {exc_type.__name__}, File: {fname}, Line: {lineno}")

    def get_instance_name(self, instance_id):
        """Function to get instance name."""
        try:
            instance = self.compute_client.get_instance(instance_id).data
            return instance.display_name
        except Exception as e:
            logger.error(f"Failed to fetch the name of instance '{instance_id}': {e}")
            self._log_exception()
            return instance_id
    
    def is_pm2_running(self, instance_name):
        """Check if PM2 is installed on the instance by checking its version."""
        try:
            # Check if PM2 is installed by running `pm2 --version`
            result = subprocess.run(['pm2', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"PM2 is installed on the instance '{instance_name}'. Version: {result.stdout.strip()}")
                return True
            else:
                logger.warning(f"PM2 command failed with exit code {result.returncode} on instance '{instance_name}'. PM2 might not be installed.")
                return False
        except FileNotFoundError:
            logger.error(f"PM2 command not found on instance '{instance_name}'. Ensure PM2 is installed.")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while checking PM2 on instance '{instance_name}': {e}")
            return False

    def get_pm2_service_status(self, instance_name):
        """Fetch PM2 service status from the instance and print details for a specific service ID."""
        try:
            result = subprocess.run(['pm2', 'status'], capture_output=True, text=True)
            if result.returncode == 0:
                # Print the entire output for debugging
                logger.info(f"PM2 services status on instance '{instance_name}':\n{result.stdout.strip()}")
                
                # Search for the specific service ID
                id = 5
                lines = result.stdout.split('\n')
                service_found = False
                
                for line in lines:
                    if f" {id} " in line:
                        # Print the service details if ID 5 is found
                        logger.info(f"Service details for ID {id}: {line.strip()}")
                        service_found = True
                        break

                if not service_found:
                    logger.info(f"Service ID {id} not found in the output.")
            else:
                logger.warning(f"PM2 command failed with exit code {result.returncode} on instance '{instance_name}'.")
        except Exception as e:
            logger.error(f"Error fetching PM2 service status from instance '{instance_name}': {e}")

    def get_instance_metrics(self):
        """Function to fetch and update all metrics for instances."""
        for instance_id in self.instances:
            instance_name = self.get_instance_name(instance_id)
            # Check if PM2 is installed and running
            if self.is_pm2_running(instance_name):
                self.get_pm2_service_status(instance_name)

if __name__ == "__main__":
    monitoring = TestPM2()
    monitoring.get_instance_metrics()
