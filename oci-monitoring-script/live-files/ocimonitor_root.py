"""
This is the latest and optimized script for OCI monitoring.
Updated on 17 July 2025.
Updated the logic to use readonly users from the updated config.json
"""

# Standard library imports
import os
import sys
import time
import logging
from datetime import datetime, timedelta
import smtplib
import subprocess
import json

# Third-party imports
import oci
import cx_Oracle
from prometheus_client import start_http_server, Gauge
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set up logging with timestamp and log level
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class MonitoringOCI:
    """Class to handle OCI monitoring, metrics collection, and alerting."""

    def __init__(self, config_file="config.json"):
        """Initialize the MonitoringOCI object with configuration from a JSON file."""
        self.config = self._load_config(config_file)

        if not self.config:
            raise ValueError("Failed to load and validate OCI configuration.")

        # Initialize clients
        self.monitoring_client = oci.monitoring.MonitoringClient(
            config=self.config["oci"]
        )
        self.load_balancer_client = oci.load_balancer.LoadBalancerClient(
            config=self.config["oci"]
        )
        self.compute_client = oci.core.ComputeClient(config=self.config["oci"])
        self.database_client = oci.database.DatabaseClient(config=self.config["oci"])

        # Extract configuration data
        self.instances = self.config.get("instances", [])
        self.db_id = self.config.get("db_details", {}).get("id")
        self.db_namespace = self.config.get("db_details", {}).get("namespace")
        self.db_list = self.config.get("db_list", [])
        self.load_balancer_id = self.config.get("load_balancer", {}).get("id")
        self.cpu_utilization_limit = int(
            self.config.get("resource_limits", {}).get("cpu_utilization_limit", 80)
        )
        self.memory_utilization_limit = int(
            self.config.get("resource_limits", {}).get("memory_utilization_limit", 80)
        )

        # tablespace alert threshold (percent)
        self.tablespace_utilization_limit = int(
            self.config.get("resource_limits", {}).get("tablespace_utilization_limit", 80)
        )

        # tablespace alert cooldown in hours (default 24)
        self.tablespace_alert_cooldown_hours = int(
            self.config.get("resource_limits", {}).get("tablespace_alert_cooldown_hours", 24)
        )

        # Initialize Prometheus metrics
        self.metrics = {
            "cpu_utilization": Gauge(
                "oci_instance_cpu_utilization",
                "CPU Utilization of OCI instance",
                ["instance_name", "instance_id"],
            ),
            "memory_utilization": Gauge(
                "oci_instance_memory_utilization",
                "Memory Utilization of OCI instance",
                ["instance_name", "instance_id"],
            ),
            "filesystem_utilization": Gauge(
                "oci_instance_filesystem_utilization",
                "Filesystem utilization percentage of OCI instance",
                ["instance_name", "instance_id", "mount"],
            ),
            "filesystem_total_bytes": Gauge(
                "oci_instance_filesystem_total_bytes",
                "Total filesystem size in bytes of OCI instance",
                ["instance_name", "instance_id", "mount"],
            ),
            "disk_read_io": Gauge(
                "oci_instance_disk_read_io",
                "Disk Read I/O of the OCI instance",
                ["instance_name", "instance_id"],
            ),
            "disk_write_io": Gauge(
                "oci_instance_disk_write_io",
                "Disk Write I/O of the OCI instance",
                ["instance_name", "instance_id"],
            ),
            "network_received_io": Gauge(
                "oci_instance_network_received_io",
                "Network Received I/O of the OCI instance",
                ["instance_name", "instance_id"],
            ),
            "network_transmitted_io": Gauge(
                "oci_instance_network_transmitted_io",
                "Network Transmitted I/O of the OCI instance",
                ["instance_name", "instance_id"],
            ),
            "lb_health": Gauge(
                "oci_load_balancer_health",
                "Health status of OCI Load Balancer",
                ["load_balancer_name", "load_balancer_id"],
            ),
            "backend_set_health": Gauge(
                "oci_backend_set_health",
                "Health status of OCI Load Balancer Backend Set",
                ["load_balancer_name", "load_balancer_id", "backend_set_name"],
            ),
            "instance_status": Gauge(
                "oci_instance_status",
                "Status of OCI instance",
                ["instance_name", "instance_id"],
            ),
            "db_cpu_utilization": Gauge(
                "oci_db_cpu_utilization", "CPU Utilization of OCI Database", ["db_id"]
            ),
            "db_storage_utilization": Gauge(
                "oci_db_storage_utilization",
                "Storage Utilization of OCI Database",
                ["db_id"],
            ),
            "db_password_expiry_date": Gauge(
                "oci_db_password_expiry_date",
                "Days until OCI Database password expires",
                ["db_id"],
            ),
            "dcw_cx_latest_patch_version": Gauge(
                "dcw_cx_latest_patch_version",
                "Latest Patch Version of DCW-CX",
                ["version"],
            ),
            "entergy_cx_latest_patch_version": Gauge(
                "entergy_cx_latest_patch_version",
                "Latest Patch Version of Entergy-CX",
                ["version"],
            ),
            "db_active_users": Gauge(
                "oci_db_active_users",
                "Count of active users in the OCI Database",
                ["db_id", "schema"],
            ),
            "cx_active_users": Gauge(
                "cx_active_users",
                "Count of active users in the OCI Database",
                ["db_id"],
            ),
            "oracle_tablespace_used_pct": Gauge(
                "oracle_tablespace_used_pct",
                "Used percent of current allocated size",
                ["db_name", "tablespace"]
            )
        }

        # Initialize SMTP configurations
        email_config = self.config.get("email", {})

        # self.smtp_config = {
        #     "sender_email_key": email_config.get("sender_email_key", "").encode(),
        #     "sender_email_encrypted_string": email_config.get(
        #         "sender_email_encrypted_string", ""
        #     ).encode(),
        #     "smtp_server_key": email_config.get("smtp_server_key", "").encode(),
        #     "smtp_server_encrypted_string": email_config.get(
        #         "smtp_server_encrypted_string", ""
        #     ).encode(),
        #     "smtp_password_key": email_config.get("smtp_password_key", "").encode(),
        #     "smtp_password_encrypted_string": email_config.get(
        #         "smtp_password_encrypted_string", ""
        #     ).encode(),
        #     "smtp_username_key": email_config.get("smtp_username_key", "").encode(),
        #     "smtp_username_encrypted_string": email_config.get(
        #         "smtp_username_encrypted_string", ""
        #     ).encode(),
        #     "smtp_port": email_config.get("smtp_port", 587),
        #     # "receiver_email_list": email_config.get("receiver_email_list", []),
        #     "core_recipients": email_config.get("core_recipients", []),
        #     "internal_recipients": email_config.get("internal_recipients", []),
        #     "external_recipients": email_config.get("external_recipients", []),
        # }

        self.smtp_config = {
            "sender_email": email_config.get("sender_email", ""),
            "smtp_server": email_config.get("smtp_server", ""),
            "smtp_port": email_config.get("smtp_port", 587),
            "smtp_username": email_config.get("smtp_username", ""),
            "smtp_password": email_config.get("smtp_password", ""),
            "core_recipients": email_config.get("core_recipients", []),
            "internal_recipients": email_config.get("internal_recipients", []),
            "external_recipients": email_config.get("external_recipients", []),
        }

        # Initialize alert status and timestamps
        self.cpu_alert_sent = {}
        self.memory_alert_sent = {}
        self.db_cpu_alert_sent = {"alert": None, "resolve": None}
        self.db_storage_alert_sent = {"alert": None, "resolve": None}
        self.lb_health_alert_sent = {"alert": None, "resolve": None}
        self.backend_set_health_alert_sent = {}

        self.password_expiry_warning_days = 7
        self.password_expiry_alert_sent = {}

        self.tablespace_alert_sent = {}   # { "DB|TS" : {"alert": datetime, "resolve": datetime} }

    def _load_config(self, file_path='config.json'):
        """Load configuration from a JSON file and validate it."""
        try:
            with open(file_path, 'r') as file:
                config = json.load(file)

            # Validate main configuration sections
            required_sections = ['oci', 'load_balancer', 'instances', 'email', 'resource_limits', 'db_details', 'db_list']
            missing_sections = [section for section in required_sections if section not in config]
            if missing_sections:
                logger.error(f"Missing configuration sections: {missing_sections}")
                return None

            # Additional validation for OCI config
            required_oci_keys = ['region', 'user', 'key_file', 'fingerprint', 'tenancy']
            missing_oci_keys = [key for key in required_oci_keys if not config['oci'].get(key)]
            if missing_oci_keys:
                logger.error(f"Missing OCI configuration keys: {missing_oci_keys}")
                return None

            # Validate 'instances' configuration
            if not isinstance(config['instances'], list) or not all(isinstance(i, str) for i in config['instances']):
                logger.error("Invalid 'instances' configuration: must be a list of strings.")
                return None

            logger.info("Configuration loaded and validated successfully.")
            return config

        except FileNotFoundError:
            logger.error(f"Configuration file not found: {file_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from the file: {file_path}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error while loading config: {e}")
            sys.exit(1)

    def _log_exception(self):
        """Utility function to log the exception details including type, file, and line number."""
        exc_type, exc_obj, exc_tb = sys.exc_info()
        if exc_type:
            fname = os.path.basename(exc_tb.tb_frame.f_code.co_filename)
            lineno = exc_tb.tb_lineno
            logger.error(f"Exception type: {exc_type.__name__}, File: {fname}, Line: {lineno}")

    def _print_blank_line(self):
        """Utility function to print a blank line for visual separation.""" 
        print()

    # def _decrypt_string(self, key, encrypted_string):
    #     """Function to decrypt an encrypted string using a given key."""
    #     try:
    #         cipher_suite = Fernet(key)
    #         decrypted_string = cipher_suite.decrypt(encrypted_string).decode()
    #         return decrypted_string
    #     except Exception as e:
    #         logger.error(f"Decryption error: {e}")
    #         self._log_exception()
    #         raise

    def _is_valid_email(self, email):
        """Utility function to validate email addresses."""
        import re
        email_regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        try:
            return re.match(email_regex, email) is not None
        except re.error as e:
            logger.error(f"Regex error while validating email '{email}': {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while validating email '{email}': {e}")
            return False

    def send_email(self, receiver_type, subject, message, alert_type):
        """Function to send an email with the given subject and message based on the receiver type."""

        # Define recipient lists based on type
        core_recipients = self.smtp_config.get("core_recipients", [])
        internal_recipients = self.smtp_config.get("internal_recipients", [])
        external_recipients = self.smtp_config.get("external_recipients", [])

        # Determine recipients based on alert type
        if receiver_type == 'core':
            receiver_list = core_recipients
        elif receiver_type == 'internal':
            receiver_list = core_recipients + internal_recipients
        elif receiver_type == 'external':
            receiver_list = core_recipients + external_recipients
        elif receiver_type == 'common':
            receiver_list = core_recipients + internal_recipients + external_recipients
        else:
            logger.warning(f"Invalid receiver type: {receiver_type}")
            return False

        # Check if the receiver list is empty
        if not receiver_list:
            logger.info(f"No recipients found in '{receiver_type}' type. Email not sent.")
            return False

        # Decrypt email credentials and server info
        try:
            email_body = MIMEText(message, 'plain')
            # sender_email = self._decrypt_string(self.smtp_config['sender_email_key'], self.smtp_config['sender_email_encrypted_string'])
            # smtp_server = self._decrypt_string(self.smtp_config['smtp_server_key'], self.smtp_config['smtp_server_encrypted_string'])
            # smtp_username = self._decrypt_string(self.smtp_config['smtp_username_key'], self.smtp_config['smtp_username_encrypted_string'])
            # smtp_password = self._decrypt_string(self.smtp_config['smtp_password_key'], self.smtp_config['smtp_password_encrypted_string'])

            sender_email = self.smtp_config['sender_email']
            smtp_server = self.smtp_config['smtp_server']
            smtp_username = self.smtp_config['smtp_username']
            smtp_password = self.smtp_config['smtp_password']

            # Send email to each recipient in the determined list
            valid_email_count = 0
            with smtplib.SMTP(smtp_server, self.smtp_config['smtp_port']) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                for receiver_email in receiver_list:
                    if not self._is_valid_email(receiver_email):
                        logger.warning(f"Invalid email address: {receiver_email}. Email not sent.")
                        continue
                    email = MIMEMultipart()
                    email['From'] = sender_email
                    email['To'] = receiver_email
                    email['Subject'] = subject
                    email.attach(email_body)
                    server.sendmail(sender_email, receiver_email, email.as_string())
                    valid_email_count += 1

            if valid_email_count > 0:
                logger.info(f"{alert_type} email sent successfully to {valid_email_count} recipient(s).")
                return True
            else:
                logger.info(f"No valid email addresses to send {alert_type} emails.")
                return False

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication Error: {e}")
            self._log_exception()
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection Error: {e}")
            self._log_exception()
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP Error: {e}")
            self._log_exception()
            return False
        except Exception as e:
            logger.error(f"An error occurred while sending email: {e}")
            self._log_exception()
            return False
        
    def get_instance_name(self, instance_id):
        """Function to get instance name."""
        try:
            instance = self.compute_client.get_instance(instance_id).data
            return instance.display_name
        except Exception as e:
            logger.error(f"Failed to fetch the name of instance '{instance_id}': {e}")
            self._log_exception()
            return instance_id

    def get_instance_status(self, instance_id, instance_name, gauge):
        """Function to fetch and update the status of an OCI instance."""
        try:
            instance = self.compute_client.get_instance(instance_id).data
            instance_status = instance.lifecycle_state

            status_mapping = {
                'PROVISIONING': 1,
                'RUNNING': 2,
                'STARTING': 3,
                'STOPPING': 4,
                'STOPPED': 5,
                'TERMINATING': 6,
                'TERMINATED': 7
            }

            instance_status_value = status_mapping.get(instance_status, 0)
            gauge.labels(instance_name=instance_name, instance_id=instance_id).set(instance_status_value)
            return instance_status, instance_status_value

        except oci.exceptions.ServiceError as e:
            logger.error(f"OCI Service Error: {e}")
            self._log_exception()
        except Exception as e:
            logger.error(f"Failed to fetch the status of instance '{instance_name}': {e}")
            self._log_exception()

    def get_instance_cpu_utilization(self, instance_id, instance_name, instance_status_value):
        """Fetch and update CPU utilization of an OCI instance, send alerts and resolve emails as needed."""
        try:
            # If instance is not RUNNING, clear the metric and return
            if instance_status_value != 2:
                logger.warning(f"CPU utilization data not available as the instance '{instance_name}' is not running.")

                # Clear the metric if it exists
                if 'cpu_utilization' in self.metrics:
                    labels = self.metrics['cpu_utilization'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['cpu_utilization'].remove(instance_name, instance_id)
                return

            # Fetch CPU utilization from OCI Monitoring
            response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''CPUUtilization[1m]{{resourceId="{instance_id}"}}.mean()'''
                )
            )

            # Process response and calculate CPU utilization
            if response.data:
                cpu_utilization = response.data[0].aggregated_datapoints[-1].value
                cpu_utilization = round(cpu_utilization, 2)
                logger.info(f"CPU utilization: {cpu_utilization}%.")

                # Update Prometheus metrics
                self.metrics['cpu_utilization'].labels(instance_name=instance_name, instance_id=instance_id).set(cpu_utilization)

                # Initialize alert status for the specific instance if it doesn't exist
                if instance_id not in self.cpu_alert_sent:
                    self.cpu_alert_sent[instance_id] = {'alert': None, 'resolve': None}

                # Get current time and last alert/resolve timestamps
                current_time = datetime.now()
                alert_info = self.cpu_alert_sent.get(instance_id, {})
                last_alert = alert_info.get('alert')
                last_resolve = alert_info.get('resolve')

                if cpu_utilization > self.cpu_utilization_limit:
                    # Send alert if no alert was sent in the last 2 hours
                    if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                        subject = f"CPU utilization alert for instance '{instance_name}'"
                        message = f"CPU utilization of instance '{instance_name}' is above {self.cpu_utilization_limit}%. Current: {cpu_utilization}%."

                        email_sent = self.send_email('core', subject, message, 'CPU utilization alert')

                        # Only update timestamps if the email was successfully sent
                        if email_sent:
                            self.cpu_alert_sent[instance_id] = {'alert': current_time, 'resolve': None}
                    else:
                        logger.info(f"CPU alert email skipped; recently sent at {last_alert}.")
                else:
                    # CPU utilization is below the limit; send a resolve email if needed
                    if last_alert and last_resolve is None:
                        subject = f"CPU utilization resolved for instance '{instance_name}'"
                        message = f"CPU utilization of instance '{instance_name}' is back within limits. Current: {cpu_utilization}%."

                        # Attempt to send the resolve email to 'core' recipients
                        email_sent = self.send_email('core', subject, message, 'CPU utilization resolution')

                        # Only update the resolve timestamp if the email was sent successfully
                        if email_sent:
                            self.cpu_alert_sent[instance_id] = {'alert': last_alert, 'resolve': current_time}
            else:
                logger.warning("CPU utilization data not found.")

        except oci.exceptions.ServiceError as e:
            logger.error(f"OCI Service Error: {e}")
            self._log_exception()
        except Exception as e:
            logger.error(f"Failed to fetch CPU utilization for instance '{instance_name}': {e}")
            self._log_exception()

    def get_instance_memory_utilization(self, instance_id, instance_name, instance_status_value):
        """Fetch and update memory utilization of an OCI instance, send alerts and resolve emails as needed."""
        try:
            # If instance is not RUNNING, clear the metric and return
            if instance_status_value != 2:
                logger.warning(f"Memory utilization data not available as the instance '{instance_name}' is not running.")

                # Clear the metric if it exists
                if 'memory_utilization' in self.metrics:
                    labels = self.metrics['memory_utilization'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['memory_utilization'].remove(instance_name, instance_id)
                return

            # Fetch memory utilization from OCI Monitoring
            response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''MemoryUtilization[1m]{{resourceId="{instance_id}"}}.mean()'''
                )
            )

            # Process response and calculate memory utilization
            if response.data:
                memory_utilization = response.data[0].aggregated_datapoints[-1].value
                memory_utilization = round(memory_utilization, 2)
                logger.info(f"Memory utilization: {memory_utilization}%.")

                # Update Prometheus metrics
                self.metrics['memory_utilization'].labels(instance_name=instance_name, instance_id=instance_id).set(memory_utilization)

                # Initialize alert status for the specific instance if it doesn't exist
                if instance_id not in self.memory_alert_sent:
                    self.memory_alert_sent[instance_id] = {'alert': None, 'resolve': None}

                # Get current time and last alert/resolve timestamps
                current_time = datetime.now()
                alert_info = self.memory_alert_sent.get(instance_id, {})
                last_alert = alert_info.get('alert')
                last_resolve = alert_info.get('resolve')

                if memory_utilization > self.memory_utilization_limit:
                    # Send alert if no alert was sent in the last 2 hours
                    if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                        subject = f"Memory utilization alert for instance '{instance_name}'"
                        message = f"Memory utilization of instance '{instance_name}' is above {self.memory_utilization_limit}%. Current: {memory_utilization}%."

                        # Attempt to send the email and store the result in a flag
                        email_sent = self.send_email('core', subject, message, 'Memory utilization alert')

                        # Only update timestamps if the email was successfully sent
                        if email_sent:
                            self.memory_alert_sent[instance_id] = {'alert': current_time, 'resolve': None}
                    else:
                        logger.info(f"Memory alert email skipped; recently sent at {last_alert}.")
                else:
                    # Memory utilization is below the limit; send a resolve email if needed
                    if last_alert and last_resolve is None:
                        subject = f"Memory utilization resolved for instance '{instance_name}'"
                        message = f"Memory utilization of instance '{instance_name}' is back within limits. Current: {memory_utilization}%."

                        # Attempt to send the resolve email and store the result
                        email_sent = self.send_email('core', subject, message, 'Memory utilization resolution')

                        # Only update the resolve timestamp if the email was sent successfully
                        if email_sent:
                            self.memory_alert_sent[instance_id] = {'alert': last_alert, 'resolve': current_time}

            else:
                logger.warning(f"Memory utilization data not found.")

        except oci.exceptions.ServiceError as e:
            logger.error(f"OCI Service Error: {e}")
            self._log_exception()
        except Exception as e:
            logger.error(f"Failed to fetch memory utilization for instance '{instance_name}': {e}")
            self._log_exception()

    def get_filesystem_utilization(self, instance_id, instance_name, instance_status_value):
        """Fetch and update filesystem utilization for an OCI instance."""
        try:
            if instance_status_value != 2:
                logger.warning(f"Filesystem utilization data not available as the instance '{instance_name}' is not running.")
                # Remove metrics for all mounts (optional: you may want to keep old data)
                return

            # Fetch FilesystemUtilization metric from OCI Monitoring
            response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    # FilesystemUtilization
                    query=f'''FilesystemUtilization[1m]{{resourceId="{instance_id}"}}.mean()'''
                )
            )

            if response.data:
                for metric in response.data:
                    mount = metric.dimensions.get("mount", "unknown")
                    datapoints = metric.aggregated_datapoints
                    if datapoints:
                        utilization = round(datapoints[-1].value, 2)
                        self.metrics['filesystem_utilization'].labels(
                            instance_name=instance_name, instance_id=instance_id, mount=mount
                        ).set(utilization)
                        logger.info(f"Filesystem utilization for '{instance_name}' ({mount}): {utilization}%")
            else:
                logger.warning(f"Filesystem utilization data not found for instance '{instance_name}'.")

            # Optionally, fetch total bytes (FilesystemSizeBytes)
            response_size = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    # FilesystemSizeBytes
                    query=f'''FilesystemSizeBytes[1m]{{resourceId="{instance_id}"}}.mean()'''
                )
            )
            if response_size.data:
                for metric in response_size.data:
                    mount = metric.dimensions.get("mount", "unknown")
                    datapoints = metric.aggregated_datapoints
                    if datapoints:
                        total_bytes = int(datapoints[-1].value)
                        self.metrics['filesystem_total_bytes'].labels(
                            instance_name=instance_name, instance_id=instance_id, mount=mount
                        ).set(total_bytes)
                        logger.info(f"Filesystem total size for '{instance_name}' ({mount}): {total_bytes} bytes")
            else:
                logger.warning(f"Filesystem size data not found for instance '{instance_name}'.")

        except Exception as e:
            logger.error(f"Failed to fetch filesystem utilization for instance '{instance_name}': {e}")
            self._log_exception()

    def get_disk_io(self, instance_id, instance_name, instance_status_value):
        """Function to fetch and log disk I/O metrics for an OCI instance."""
        try:
            # If instance is not RUNNING, clear the metric
            if instance_status_value != 2:
                logger.warning(f"Disk I/O data not available as the instance is not running.")

                # Check if the metric exists before removing it
                if 'disk_read_io' in self.metrics:
                    labels = self.metrics['disk_read_io'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['disk_read_io'].remove(instance_name, instance_id)

                if 'disk_write_io' in self.metrics:
                    labels = self.metrics['disk_write_io'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['disk_write_io'].remove(instance_name, instance_id)

                return

            # Get Disk Read I/O
            read_io_response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''DiskIopsRead[1m]{{resourceId="{instance_id}"}}.rate()'''
                )
            )

            if read_io_response.data:
                disk_read_io = read_io_response.data[0].aggregated_datapoints[-1].value
                disk_read_io = round(disk_read_io, 2)
                self.metrics['disk_read_io'].labels(instance_name=instance_name, instance_id=instance_id).set(disk_read_io)
                logger.info(f"Disk Read I/O: {disk_read_io} IOPS")
            else:
                logger.warning(f"Disk Read I/O data not found.")

            time.sleep(0.5)

            # Get Disk Write I/O
            write_io_response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''DiskIopsWritten[1m]{{resourceId="{instance_id}"}}.rate()'''
                )
            )

            if write_io_response.data:
                disk_write_io = write_io_response.data[0].aggregated_datapoints[-1].value
                disk_write_io = round(disk_write_io, 2)
                self.metrics['disk_write_io'].labels(instance_name=instance_name, instance_id=instance_id).set(disk_write_io)
                logger.info(f"Disk Write I/O: {disk_write_io} IOPS")
            else:
                logger.warning(f"Disk Write I/O data not found.")

        except Exception as e:
            logger.error(f"Failed to fetch disk I/O: {e}")
            self._log_exception()

    def get_network_io(self, instance_id, instance_name, instance_status_value):
        """Function to fetch and log network I/O metrics for an OCI instance."""
        try:
            # If instance is not RUNNING, clear the metric
            if instance_status_value != 2:
                logger.warning(f"Network I/O data not available as the instance is not running.")

                # Check if the metric exists before removing it
                if 'network_received_io' in self.metrics:
                    labels = self.metrics['network_received_io'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['network_received_io'].remove(instance_name, instance_id)

                if 'network_transmitted_io' in self.metrics:
                    labels = self.metrics['network_transmitted_io'].labels(instance_name=instance_name, instance_id=instance_id)
                    if labels:
                        self.metrics['network_transmitted_io'].remove(instance_name, instance_id)

                return

            # Get Network Received Bytes
            received_io_response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''NetworksBytesIn[1m]{{resourceId="{instance_id}"}}.rate()'''
                )
            )

            if received_io_response.data:
                network_received_io = received_io_response.data[0].aggregated_datapoints[-1].value
                network_received_io = round(network_received_io, 2)
                self.metrics['network_received_io'].labels(instance_name=instance_name, instance_id=instance_id).set(network_received_io)
                logger.info(f"Network Received I/O: {network_received_io} bytes/sec")
            else:
                logger.warning(f"Network Received I/O data not found.")

            time.sleep(0.5)

            # Get Network Transmit Bytes
            transmitted_io_response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace="oci_computeagent",
                    query=f'''NetworksBytesOut[1m]{{resourceId="{instance_id}"}}.rate()'''
                )
            )

            if transmitted_io_response.data:
                network_transmitted_io = transmitted_io_response.data[0].aggregated_datapoints[-1].value
                network_transmitted_io = round(network_transmitted_io, 2)
                self.metrics['network_transmitted_io'].labels(instance_name=instance_name, instance_id=instance_id).set(network_transmitted_io)
                logger.info(f"Network Transmitted I/O: {network_transmitted_io} bytes/sec")
            else:
                logger.warning(f"Network Transmitted I/O data not found.")

        except Exception as e:
            logger.error(f"Failed to fetch network I/O: {e}")
            self._log_exception()

    def get_instance_metrics(self):
        """Function to fetch and update all metrics for instances."""
        for instance_id in self.instances:
            instance_name = self.get_instance_name(instance_id)
            instance_status, instance_status_value = self.get_instance_status(instance_id, instance_name, self.metrics['instance_status'])

            logger.info(f"Status of instance '{instance_name}': {instance_status}")
            time.sleep(0.5)

            self.get_instance_cpu_utilization(instance_id, instance_name, instance_status_value)
            time.sleep(0.5)

            self.get_instance_memory_utilization(instance_id, instance_name, instance_status_value)
            time.sleep(0.5)

            self.get_filesystem_utilization(instance_id, instance_name, instance_status_value)  # <-- Add this line
            self._print_blank_line()
            time.sleep(0.5)

            self.get_disk_io(instance_id, instance_name, instance_status_value)
            time.sleep(0.5)

            self.get_network_io(instance_id, instance_name, instance_status_value)
            self._print_blank_line()
            time.sleep(0.5)

            # # Check if PM2 is installed and running
            # self.is_pm2_running(instance_name)
            # self._print_blank_line()
            # time.sleep(0.5)

            # # Check if PM2 is installed and running
            # if self.is_pm2_running(instance_name):
            #     self.get_pm2_service_status(instance_name)

            # self._print_blank_line()
            # time.sleep(0.5)

    # def is_pm2_running(self, instance_name):
    #     """Check if PM2 is installed on the instance by checking its version."""
    #     try:
    #         # Check if PM2 is installed by running `pm2 --version`
    #         result = subprocess.run(['pm2', '--version'], capture_output=True, text=True)
    #         if result.returncode == 0:
    #             logger.info(f"PM2 is installed on the instance '{instance_name}'. Version: {result.stdout.strip()}")
    #             return True
    #         else:
    #             logger.warning(f"PM2 command failed with exit code {result.returncode} on instance '{instance_name}'. PM2 might not be installed.")
    #             return False
    #     except FileNotFoundError:
    #         logger.error(f"PM2 command not found on instance '{instance_name}'. Ensure PM2 is installed.")
    #         return False
    #     except Exception as e:
    #         logger.error(f"An unexpected error occurred while checking PM2 on instance '{instance_name}': {e}")
    #         return False

    # def get_pm2_service_status(self, instance_name):
    #     """Fetch PM2 service status from the instance."""
    #     try:
    #         result = subprocess.run(['pm2', 'status'], capture_output=True, text=True, check=True)
    #         print(result.stdout.strip())
    #     except subprocess.CalledProcessError as e:
    #         print(f"Error: {e}")

    def get_database_name(self):
        """Function to get database name."""
        try:
            database = self.database_client.get_database(self.db_id).data
            return database.db_name
        except Exception as e:
            logger.error(f"Failed to fetch the name of database '{self.db_id}': {e}")
            self._log_exception()
            return self.db_id

    def get_database_status(self):
        """Function to fetch and return the status of the database."""
        db_name = self.get_database_name()
        try:
            db_details = self.database_client.get_database(self.db_id)
            db_status = db_details.data.lifecycle_state
            # logger.info(f"Status of database '{db_name}': {db_status}")
            return db_status

        except Exception as e:
            logger.error(f"Failed to fetch the status of database '{db_name}': {e}")
            self._log_exception()
            return None

    def get_db_cpu_utilization(self):
        """Function to fetch and process CPU utilization for the database, send alerts if needed."""
        db_name = self.get_database_name()
        db_status = self.get_database_status()

        try:
            # If db is not AVAILABLE, clear the metric
            if db_status != 'AVAILABLE':
                logger.warning(f"CPU utilization data not available as the database is not active.")

                # Check if the metric exists before removing it
                if 'db_cpu_utilization' in self.metrics:
                    labels = self.metrics['db_cpu_utilization'].labels(db_id=self.db_id)
                    if labels:
                        self.metrics['db_cpu_utilization'].remove(self.db_id)
                return

            response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace=self.db_namespace,
                    query=f'''CpuUtilization[1m]{{resourceId_database="{self.db_id}"}}.mean()'''
                )
            )

            if response.data and response.data[0].aggregated_datapoints:
                db_cpu_utilization = response.data[0].aggregated_datapoints[-1].value
                db_cpu_utilization = round(db_cpu_utilization, 2)
                logger.info(f"CPU utilization: {db_cpu_utilization}%")

                # Update the Prometheus metrics
                self.metrics['db_cpu_utilization'].labels(self.db_id).set(db_cpu_utilization)

                # Alert and resolve logic
                current_time = datetime.now()
                last_alert = self.db_cpu_alert_sent.get('alert')
                last_resolve = self.db_cpu_alert_sent.get('resolve')

                if db_cpu_utilization > self.cpu_utilization_limit:
                    # Send alert if not sent in the last 2 hours
                    if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                        subject = f"CPU utilization alert for database '{db_name}'"
                        message = f"CPU utilization of database '{db_name}' is above {self.cpu_utilization_limit}%. Current: {db_cpu_utilization}%."
                        email_sent = self.send_email('common', subject, message, 'Database CPU utilization alert')

                        if email_sent:
                            self.db_cpu_alert_sent = {'alert': current_time, 'resolve': None}
                    else:
                        logger.info(f"Database CPU alert email skipped; recently sent at {last_alert}.")

                else:
                    # Check if a resolve email should be sent
                    if last_alert and last_resolve is None:
                        subject = f"CPU utilization resolved for database '{db_name}'"
                        message = f"CPU utilization of database '{db_name}' is back within limits. Current: {db_cpu_utilization}%."
                        email_sent = self.send_email('common', subject, message, 'Database CPU utilization resolution')

                        if email_sent:
                            self.db_cpu_alert_sent = {'alert': last_alert, 'resolve': current_time}

            else:
                logger.warning(f"CPU utilization data not found for database '{db_name}'.")

        except Exception as e:
            logger.error(f"Failed to fetch CPU utilization for database '{db_name}': {e}")
            self._log_exception()

    def get_db_storage_utilization(self):
        """Function to fetch and process storage utilization for the database."""
        db_name = self.get_database_name()
        db_status = self.get_database_status()
        
        try:
            # If db is not AVAILABLE, clear the metric
            if db_status != 'AVAILABLE':
                logger.warning(f"Storage utilization data not available as the database is not active.")

                # Check if the metric exists before removing it
                if 'db_storage_utilization' in self.metrics:
                    labels = self.metrics['db_storage_utilization'].labels(db_id=self.db_id)
                    if labels:
                        self.metrics['db_storage_utilization'].remove(self.db_id)
                return

            response = self.monitoring_client.summarize_metrics_data(
                compartment_id=self.config['oci']['tenancy'],
                summarize_metrics_data_details=oci.monitoring.models.SummarizeMetricsDataDetails(
                    namespace=self.db_namespace,
                    query=f'''StorageUtilization[60m]{{resourceId_database="{self.db_id}"}}.mean()'''
                )
            )

            if response.data and response.data[0].aggregated_datapoints:
                db_storage_utilization = response.data[0].aggregated_datapoints[-1].value
                db_storage_utilization = round(db_storage_utilization, 2)
                logger.info(f"Storage utilization: {db_storage_utilization}%")
                self.metrics['db_storage_utilization'].labels(self.db_id).set(db_storage_utilization)

                current_time = datetime.now()
                last_alert = self.db_storage_alert_sent.get('alert')
                last_resolve = self.db_storage_alert_sent.get('resolve')

                if db_storage_utilization > self.memory_utilization_limit:
                    # Send alert if not sent in the last 2 hours
                    if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                        subject = f"Storage utilization alert for database '{db_name}'"
                        message = (f"Storage utilization of database '{db_name}' is above {self.memory_utilization_limit}%. "
                                f"Current: {db_storage_utilization}%.")
                        email_sent = self.send_email('common', subject, message, 'Database storage utilization alert')

                        if email_sent:
                            self.db_storage_alert_sent = {'alert': current_time, 'resolve': None}
                    else:
                        logger.info(f"Database storage alert email skipped; recently sent at {last_alert}.")

                else:
                    # Send a resolve email if needed
                    if last_alert and last_resolve is None:
                        subject = f"Storage utilization resolved for database '{db_name}'"
                        message = (f"Storage utilization of database '{db_name}' is back within limits. "
                                f"Current: {db_storage_utilization}%.")
                        email_sent = self.send_email('common', subject, message, 'Database storage utilization resolution')

                        if email_sent:
                            self.db_storage_alert_sent = {'alert': last_alert, 'resolve': current_time}

            else:
                logger.warning(f"Storage utilization data not found for database '{db_name}'.")

        except Exception as e:
            logger.error(f"Failed to fetch storage utilization: {e}")
            self._log_exception()

    def get_database_metrics(self):
        """Function to fetch and update all database metrics."""
        db_name = self.get_database_name()
        db_status = self.get_database_status()
        logger.info(f"Status of database '{db_name}': {db_status}")
        time.sleep(0.5)

        self.get_db_cpu_utilization()
        time.sleep(0.5)

        self.get_db_storage_utilization()
        self._print_blank_line()
        time.sleep(0.5)

    def get_load_balancer_name(self, load_balancer_id):
        """Function to get load balancer name."""
        try:
            load_balancer = self.load_balancer_client.get_load_balancer(load_balancer_id).data
            return load_balancer.display_name
        except Exception as e:
            logger.error(f"Failed to fetch the name of load balancer '{load_balancer_id}': {e}")
            self._log_exception()
            return load_balancer_id

    def get_load_balancer_health(self):
        """Function to fetch the health status of the load balancer and send alerts if needed."""
        load_balancer_name = self.get_load_balancer_name(self.load_balancer_id)
        try:
            response = self.load_balancer_client.get_load_balancer_health(self.load_balancer_id)

            if response.data:
                load_balancer_health = response.data.status
                health_mapping = {
                    'OK': 1,
                    'PENDING': 2,
                    'INCOMPLETE': 3,
                    'WARNING': 4,
                    'CRITICAL': 5
                }
                load_balancer_health_value = health_mapping.get(load_balancer_health, 0)

                logger.info(f"Health status of load balancer '{load_balancer_name}': {load_balancer_health}")
                self.metrics['lb_health'].labels(load_balancer_name=load_balancer_name, load_balancer_id=self.load_balancer_id).set(load_balancer_health_value)

                current_time = datetime.now()
                last_alert = self.lb_health_alert_sent.get('alert')
                last_resolve = self.lb_health_alert_sent.get('resolve')

                if load_balancer_health != 'OK':
                    # Send an alert if not sent within the last 2 hours
                    if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                        subject = f"Health alert for load balancer '{load_balancer_name}'"
                        message = f"The health status of load balancer '{load_balancer_name}' has changed. Current: {load_balancer_health}."
                        email_sent = self.send_email('core', subject, message, 'Load balancer health alert')

                        if email_sent:
                            self.lb_health_alert_sent = {'alert': current_time, 'resolve': None}
                    else:
                        logger.info(f"Load balancer health alert email skipped; recently sent at {last_alert}.")
                else:
                    # Send a resolve email if the health is back to 'OK' and a prior alert was sent
                    if last_alert and last_resolve is None:
                        subject = f"Health resolved for load balancer '{load_balancer_name}'"
                        message = f"The health status of load balancer '{load_balancer_name}' is back to normal. Current: {load_balancer_health}."
                        email_sent = self.send_email('core', subject, message, 'Load balancer health resolution')

                        if email_sent:
                            self.lb_health_alert_sent = {'alert': last_alert, 'resolve': current_time}

            else:
                logger.warning(f"Health data not found for load balancer '{load_balancer_name}'.")

        except Exception as e:
            logger.error(f"Failed to fetch health status of load balancer '{load_balancer_name}': {e}")
            self._log_exception()

    def get_backend_set_health(self):
        """Function to fetch the health of each backend set and send alerts if needed."""
        load_balancer_name = self.get_load_balancer_name(self.load_balancer_id)
        try:
            backend_sets = self.load_balancer_client.list_backend_sets(self.load_balancer_id).data

            if backend_sets:
                for backend_set in backend_sets:
                    backend_set_name = backend_set.name
                    backend_set_health = self.load_balancer_client.get_backend_set_health(self.load_balancer_id, backend_set_name).data.status
                    health_mapping = {
                        'OK': 1,
                        'PENDING': 2,
                        'INCOMPLETE': 3,
                        'WARNING': 4,
                        'CRITICAL': 5
                    }
                    backend_set_health_value = health_mapping.get(backend_set_health, 0)

                    logger.info(f"Health status of backend set '{backend_set_name}': {backend_set_health}")
                    self.metrics['backend_set_health'].labels(
                        load_balancer_name=load_balancer_name,
                        load_balancer_id=self.load_balancer_id,
                        backend_set_name=backend_set_name
                    ).set(backend_set_health_value)

                    current_time = datetime.now()

                    # Initialize alert tracking for this backend set if not already done
                    if backend_set_name not in self.backend_set_health_alert_sent:
                        self.backend_set_health_alert_sent[backend_set_name] = {'alert': None, 'resolve': None}

                    last_alert = self.backend_set_health_alert_sent[backend_set_name].get('alert')
                    last_resolve = self.backend_set_health_alert_sent[backend_set_name].get('resolve')

                    if backend_set_health != 'OK':
                        # Send an alert if not sent within the last 2 hours
                        if last_alert is None or (current_time - last_alert) > timedelta(hours=2):
                            subject = f"Health alert for backend set '{backend_set_name}'"
                            message = f"The health status of backend set '{backend_set_name}' has changed. Current: {backend_set_health}."
                            email_sent = self.send_email('core', subject, message, 'Backend set health alert')

                            if email_sent:
                                self.backend_set_health_alert_sent[backend_set_name] = {'alert': current_time, 'resolve': None}

                        else:
                            logger.info(f"Backend set health alert email skipped; recently sent at {last_alert}.")
                    else:
                        # Send a resolve email if the health is back to 'OK' and a prior alert was sent
                        if last_alert and last_resolve is None:
                            subject = f"Health resolved for backend set '{backend_set_name}'"
                            message = f"The health status of backend set '{backend_set_name}' is back to normal. Current: {backend_set_health}."
                            email_sent = self.send_email('core', subject, message, 'Backend set health resolution')

                            if email_sent:
                                self.backend_set_health_alert_sent[backend_set_name] = {'alert': last_alert, 'resolve': current_time}

                    time.sleep(0.5)

            else:
                logger.warning("Backend set health data not found.")

        except Exception as e:
            logger.error(f"Failed to fetch backend set health: {e}")
            self._log_exception()

    # def get_password_expiry_date(self, db):
    #     """Function to fetch the password expiry date from a given database configuration."""
    #     try:
    #         # Create DSN from database configuration
    #         dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

    #         # Normal user connection
    #         connection = cx_Oracle.connect(
    #             user=db['db_user'],
    #             password=db['db_password'],
    #             dsn=dsn
    #         )
    #         logger.info(f"Connected to {db['db_name']} as {db['db_user']}")

    #         # Use the connection in a context manager to ensure it is closed properly
    #         with connection:
    #             # Create a cursor and execute the SQL query
    #             with connection.cursor() as cursor:
    #                 cursor.execute(
    #                     "SELECT USERNAME, EXPIRY_DATE FROM USER_USERS")
    #                 result = cursor.fetchone()

    #         if result:
    #             username, expiry_date = result
    #             return expiry_date  # Return as is, unless timezone is present
    #         else:
    #             logger.warning(f"No expiry date found for the username '{db['db_user']}' in DB '{db['db_name']}'.")
    #             return None

    #     except cx_Oracle.DatabaseError as e:
    #         logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
    #         self._log_exception()
    #         return None
    #     except Exception as e:
    #         logger.error(f"Unexpected error in monitoring script: {e}")
    #         self._log_exception()
    #         return None

    def get_password_expiry_date(self):
        """
        Function to fetch the password expiry date for users specified in
        password_expiry_targets using the system-level user C##READONLY.
        """
        results = {}

        try:
            # Find the system-level user credentials from db_list
            system_user_db = next(
                (db for db in self.config['db_list'] if db['db_user'] == 'C##READONLY'), None
            )
            if not system_user_db:
                logger.error("System-level user C##READONLY not found in db_list")
                return results

            for target in self.config['password_expiry_targets']:
                service_name = target['db_service_name']
                users = target['users']

                # Build DSN using system-level credentials, but target service name
                dsn = cx_Oracle.makedsn(
                    system_user_db['db_dsn'],
                    system_user_db['db_port'],
                    service_name=service_name
                )

                # Connect using C##READONLY
                connection = cx_Oracle.connect(
                    user=system_user_db['db_user'],
                    password=system_user_db['db_password'],
                    dsn=dsn
                )
                logger.info(f"Connected to {service_name} as {system_user_db['db_user']}")

                with connection:
                    with connection.cursor() as cursor:
                        # Check password expiry for each user in this target
                        for username in users:
                            cursor.execute(
                                "SELECT USERNAME, EXPIRY_DATE FROM DBA_USERS WHERE USERNAME = :u",
                                u=username
                            )
                            result = cursor.fetchone()
                            if result:
                                uname, expiry_date = result
                                results[f"{uname}@{service_name}"] = expiry_date
                            else:
                                logger.warning(f"No expiry date found for user '{username}' on {service_name}")

            return results

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error: {e}")
            self._log_exception()
            return results
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self._log_exception()
            return results
    
    # def update_password_expiry_metric(self):
    #     """Function to update the password expiry date metric and send alerts if needed."""
    #     for db in self.db_list:
    #         # Skip the SYS user in this function
    #         # if db['db_user'].upper() == 'SYS':
    #         #     logger.info(f"Skipped password expiry metric update for '{db['db_name']}' with username '{db['db_user']}'.")
    #         #     self._print_blank_line()
    #         #     continue

    #         expiry_date = self.get_password_expiry_date(db)
    #         if expiry_date:
    #             days_until_expiry = (expiry_date - datetime.now()).days
    #             self.metrics['db_password_expiry_date'].labels(self.db_id).set(days_until_expiry)
    #             logger.info(f"Password expiry date for '{db['db_name']}' with username '{db['db_user']}' is {expiry_date}. Days left: {days_until_expiry}.")

    #             # Initialize alert tracking for this DB if not already done
    #             if db['db_name'] not in self.password_expiry_alert_sent:
    #                 self.password_expiry_alert_sent[db['db_name']] = False

    #             # Send alert if days until expiry is less than or equal to the warning threshold
    #             if days_until_expiry <= self.password_expiry_warning_days:
    #                 if not self.password_expiry_alert_sent[db['db_name']]:
    #                     subject = "Alert: Database Password Expiry Approaching"
    #                     message = f"The password for the username '{db['db_user']}' in DB '{db['db_name']}' is about to expire in {days_until_expiry} days."
    #                     email_sent = self.send_email('common', subject, message, 'DB Password Expiry')
                        
    #                     if email_sent:
    #                         logger.info(f"Password expiry alert sent for '{db['db_name']}' with username '{db['db_user']}'.")
    #                         self.password_expiry_alert_sent[db['db_name']] = True

    #         self._print_blank_line()
    #         time.sleep(0.5)

    def update_password_expiry_metric(self):
        """Function to update the password expiry date metric and send alerts if needed."""
        results = self.get_password_expiry_date()  # now returns all DBs + users

        if not results:
            logger.warning("No password expiry results available.")
            return

        for user_db, expiry_date in results.items():
            days_until_expiry = (expiry_date - datetime.now()).days
            self.metrics['db_password_expiry_date'].labels(user_db).set(days_until_expiry)

            logger.info(f"Password expiry date for '{user_db}' is {expiry_date}. Days left: {days_until_expiry}.")

            # Initialize alert tracking
            if user_db not in self.password_expiry_alert_sent:
                self.password_expiry_alert_sent[user_db] = False

            # Send alert if expiry is near
            if days_until_expiry <= self.password_expiry_warning_days:
                if not self.password_expiry_alert_sent[user_db]:
                    subject = "Alert: Database Password Expiry Approaching"
                    message = f"The password for '{user_db}' is about to expire in {days_until_expiry} days."
                    email_sent = self.send_email('common', subject, message, 'DB Password Expiry')

                    if email_sent:
                        logger.info(f"Password expiry alert sent for '{user_db}'.")
                        self.password_expiry_alert_sent[user_db] = True

            self._print_blank_line()
            time.sleep(0.5)

    def get_tablespace_usage(self, db):
        """
        Connects to the given PDB using its READONLY user
        and returns list of tablespace usage rows.
        """
        try:
            dsn = cx_Oracle.makedsn(
                db['db_dsn'],
                db['db_port'],
                service_name=db['db_service_name']
            )

            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )

            query = """
            SELECT
                df.tablespace_name,

                -- Current allocated size
                ROUND(SUM(df.bytes) / 1024 / 1024, 2) AS current_mb,

                -- Max possible size with autoextend
                ROUND(SUM(df.maxbytes) / 1024 / 1024, 2) AS max_mb,

                -- Free space inside current allocation
                ROUND(NVL(fs.free_mb, 0), 2) AS free_mb,

                -- Used inside current allocation
                ROUND((SUM(df.bytes) / 1024 / 1024) - NVL(fs.free_mb, 0), 2) AS used_mb,

                -- % of current allocated
                ROUND(
                    ((SUM(df.bytes)/1024/1024) - NVL(fs.free_mb, 0))
                    / (SUM(df.bytes)/1024/1024) * 100,
                2) AS used_pct_current,

                -- % of max possible size
                ROUND(
                    ((SUM(df.bytes)/1024/1024) - NVL(fs.free_mb, 0))
                    / (SUM(df.maxbytes)/1024/1024) * 100,
                2) AS used_pct_max

            FROM
                dba_data_files df
            LEFT JOIN (
                SELECT
                    tablespace_name,
                    SUM(bytes) / 1024 / 1024 AS free_mb
                FROM
                    dba_free_space
                GROUP BY
                    tablespace_name
            ) fs
            ON df.tablespace_name = fs.tablespace_name
            GROUP BY
                df.tablespace_name, 
                fs.free_mb
            ORDER BY
                used_pct_current DESC
            """

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(query)
                    rows = cursor.fetchall()

            return rows

        except Exception as e:
            logger.error(f"Failed to fetch tablespace usage for DB {db['db_name']}: {e}")
            self._log_exception()
            return []

    def update_tablespace_metrics(self):
        """
        Loops through all PDBs with READONLY users,
        gathers tablespace usage, exports to Prometheus,
        and sends alerts.
        """
        for db in self.db_list:

            # Skip root service user
            if db["db_user"] == "C##READONLY":
                continue

            db_name = db["db_name"]

            rows = self.get_tablespace_usage(db)
            if not rows:
                continue

            for (
                ts_name,
                current_mb,
                max_mb,
                free_mb,
                used_mb,
                used_pct_current,
                used_pct_max
            ) in rows:

                # ----- LOGGING -----
                logger.info(
                    f"{db_name}.{ts_name} → {used_pct_current}% (Used: {used_mb} MB, Free: {free_mb} MB, Current: {current_mb} MB, Max: {max_mb} MB)"
                )

                # ----- EXPORT TO PROMETHEUS (ONLY 1 METRIC) -----
                self.metrics["oracle_tablespace_used_pct"].labels(db_name, ts_name).set(used_pct_current)

                # ----- ALERT LOGIC -----
                key = f"{db_name}|{ts_name}"

                if key not in self.tablespace_alert_sent:
                    self.tablespace_alert_sent[key] = {"alert": None, "resolve": None}

                now = datetime.now()
                last_alert = self.tablespace_alert_sent[key]["alert"]
                last_resolve = self.tablespace_alert_sent[key]["resolve"]

                alert_limit = self.tablespace_utilization_limit

                # cooldown (timedelta) read from config; default should be set in __init__
                cooldown = timedelta(hours=getattr(self, "tablespace_alert_cooldown_hours", 24))

                # ---- ALERT ----
                if used_pct_current >= alert_limit:

                    # Send only if never alerted OR cooldown has passed
                    if last_alert is None or (now - last_alert) > cooldown:

                        subject = f"Tablespace Alert: {ts_name} in {db_name}"
                        message = (
                            f"Tablespace '{ts_name}' in DB '{db_name}' is {used_pct_current}% full.\n\n"
                            f"Details:\n"
                            f"  - Used: {used_mb} MB\n"
                            f"  - Free: {free_mb} MB\n"
                            f"  - Current Size: {current_mb} MB\n"
                            f"  - Max Size: {max_mb} MB\n"
                            f"  - % of max used: {used_pct_max}%\n"
                        )

                        email_sent = self.send_email("external", subject, message, "Tablespace Alert")
                        if email_sent:
                            self.tablespace_alert_sent[key]["alert"] = now
                            self.tablespace_alert_sent[key]["resolve"] = None
                            logger.info(f"Tablespace alert email sent for {key} at {now.isoformat()}")
                    else:
                        # Cooldown not passed — skip sending, but log it
                        next_allowed = last_alert + cooldown
                        logger.info(
                            f"Skipping tablespace alert for {key}: still in cooldown until {next_allowed.isoformat()} "
                            f"(last alert at {last_alert.isoformat()})."
                        )

                # ---- RESOLVED ----
                else:
                    if last_alert is not None and last_resolve is None:

                        subject = f"Tablespace Resolved: {ts_name} in {db_name}"
                        message = (
                            f"Tablespace '{ts_name}' in DB '{db_name}' has returned to normal.\n"
                            f"Current Usage: {used_pct_current}%"
                        )

                        email_sent = self.send_email("external", subject, message, "Tablespace Resolved")
                        if email_sent:
                            self.tablespace_alert_sent[key]["resolve"] = now
                            logger.info(f"Tablespace resolve email sent for {key} at {now.isoformat()}")

    def get_active_cx_users_count(self, db):
        """Function to fetch the active user count from a given database configuration."""
        try:
            # Create DSN from database configuration
            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # Connect using context manager to ensure proper resource handling
            with cx_Oracle.connect(user=db['db_user'], password=db['db_password'], dsn=dsn) as connection:
                logger.info(f"Connected to {db['db_name']} as {db['db_user']} (Normal)")

                # Execute query and fetch result within a cursor
                with connection.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM USER_LOGIN_HISTORY WHERE IS_ACTIVE = 1")
                    result = cursor.fetchone()

            # Check and return result
            if result:
                return result[0]  # Return active user count
            else:
                logger.warning(f"No active user found in DCW CX Application.")
                return None

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return None
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return None

    def show_active_cx_users_count(self):
        """Function to log active users for databases with 'DCWATER_EXCHANGE' user."""
        # Filter the db_list to include only databases where the user is 'DCWATER_EXCHANGE'
        dcwater_dbs = [db for db in self.db_list if db['db_user'] == 'READONLY' and db['db_name'] == 'CURADCWATER']

        # Iterate only through the filtered list
        for db in dcwater_dbs:
            is_active = self.get_active_cx_users_count(db)
            logger.info(f"Count of active users in DCW CX Application: {is_active}")
            self.metrics['cx_active_users'].labels(db_id=self.db_id).set(is_active)
        if is_active is None:
            # Clear the gauge if is_active is None
            self.metrics['cx_active_users'].labels(db_id=self.db_id).remove(self.db_id)

    def get_dcw_cx_latest_patch_version(self):
        db = self.config['db_list'][0]

        # Extract the database connection details for the third DB (CURAENTERGYSTAGE)
        db_dsn = db['db_dsn']
        db_port = db['db_port']
        db_service_name = db['db_service_name']
        db_user = db['db_user']
        db_password = db['db_password']
        # Create the DSN (Data Source Name) using the instance attributes
        dsn_tns = cx_Oracle.makedsn(db_dsn, db_port, service_name=db_service_name)

        # Establish the database connection
        connection = cx_Oracle.connect(user=db_user, password=db_password, dsn=dsn_tns)

        try:
            cursor = connection.cursor()
            query = """
            SELECT pd.PATCH_VERSION
            FROM PATCH_DETAILS pd
            ORDER BY pd.PATCH_DATE DESC
            FETCH FIRST 1 ROWS ONLY
            """
            cursor.execute(query)

            # Fetch the result
            result = cursor.fetchone()

            if result:
                latest_patch_version = result[0]

                # Log the latest patch version
                logger.info(f"DCW-CX Latest Patch Version: {latest_patch_version}")

                # Update Prometheus gauge with the version label and a placeholder value
                # If using a gauge, set a numeric value. For example, you might use 1 to indicate the presence of a version.
                self.metrics['dcw_cx_latest_patch_version'].labels(version=latest_patch_version).set(1)
                return latest_patch_version

            else:
                # Handle the case where no patch details are found
                logger.info("No patch details found.")
                self.metrics['dcw_cx_latest_patch_version'].labels(version='unknown').set(0)
                return None

        finally:
            # Close the cursor and connection
            cursor.close()
            connection.close()

    # def get_entergy_cx_latest_patch_version(self):
    #     db = self.config['db_list'][1]

    #     # Extract the database connection details for the third DB (CURAENTERGYSTAGE)
    #     db_dsn = db['db_dsn']
    #     db_port = db['db_port']
    #     db_service_name = db['db_service_name']
    #     db_user = db['db_user']
    #     db_password = db['db_password']
    #     # Create the DSN (Data Source Name) using the instance attributes
    #     dsn_tns = cx_Oracle.makedsn(db_dsn, db_port, service_name=db_service_name)

    #     # Establish the database connection
    #     connection = cx_Oracle.connect(user=db_user, password=db_password, dsn=dsn_tns)

    #     try:
    #         cursor = connection.cursor()
    #         query = """
    #         SELECT pd.PATCH_VERSION
    #         FROM PATCH_DETAILS pd
    #         ORDER BY pd.PATCH_DATE DESC
    #         FETCH FIRST 1 ROWS ONLY
    #         """
    #         cursor.execute(query)

    #         # Fetch the result
    #         result = cursor.fetchone()

    #         if result:
    #             latest_patch_version = result[0]

    #             # Log the latest patch version
    #             logger.info(f"Entergy-CX Latest Patch Version: {latest_patch_version}")

    #             # Update Prometheus gauge with the version label and a placeholder value
    #             # If using a gauge, set a numeric value. For example, you might use 1 to indicate the presence of a version.
    #             self.metrics['entergy_cx_latest_patch_version'].labels(version=latest_patch_version).set(1)
    #             return latest_patch_version

    #         else:
    #             # Handle the case where no patch details are found
    #             logger.info("No patch details found.")
    #             self.metrics['entergy_cx_latest_patch_version'].labels(version='unknown').set(0)
    #             return None

    #     finally:
    #         # Close the cursor and connection
    #         cursor.close()
    #         connection.close()

    def get_active_users_for_entergy_cura_stage(self, db):
        """Fetch active users for ENTERGY_CURA_STAGE schema."""
        try:
            db_status = self.get_database_status()  # Placeholder function to get DB status

            if db_status != 'AVAILABLE':
                logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
                return 0

            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # connection = cx_Oracle.connect(
            #     user=db['db_user'], 
            #     password=db['db_password'],
            #     dsn=dsn, 
            #     mode=cx_Oracle.SYSDBA
            # )
            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )
            logger.info(f"Connected to {db['db_name']} as {db['db_user']}")

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM(
                            SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
                            FROM V$SESSION
                            WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'ENTERGY_CURA_STAGE'
                        )
                        """
                    )
                    result = cursor.fetchone()

            if result and result[0] > 0:
                active_users_count = result[0]
                logger.info(f"Count of active users in ENTERGY_CURA_STAGE: {active_users_count}")
                return active_users_count
            else:
                logger.warning(f"No active users found in schema 'ENTERGY_CURA_STAGE'.")
                return 0

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return 0
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return 0

    def get_active_users_for_entergy_cura_prod(self, db):
        """Fetch active users for ENTERGY_CURA_PROD schema."""
        try:
            db_status = self.get_database_status()

            if db_status != 'AVAILABLE':
                logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
                return 0

            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # connection = cx_Oracle.connect(
            #     user=db['db_user'], 
            #     password=db['db_password'],
            #     dsn=dsn, 
            #     mode=cx_Oracle.SYSDBA
            # )
            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )            
            logger.info(f"Connected to {db['db_name']} as {db['db_user']} (SYSDBA)")

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM(
                            SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
                            FROM V$SESSION
                            WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'ENTERGY_CURA_PROD'
                        )
                        """
                    )
                    result = cursor.fetchone()

            if result and result[0] > 0:
                active_users_count = result[0]
                logger.info(f"Count of active users in ENTERGY_CURA_PROD: {active_users_count}")
                return active_users_count
            else:
                logger.warning(f"No active users found in schema 'ENTERGY_CURA_PROD'.")
                return 0

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return 0
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return 0

    def get_active_users_for_dcwater_exchange(self, db):
        """Fetch active users for DCWATER_EXCHANGE schema."""
        try:
            db_status = self.get_database_status()

            if db_status != 'AVAILABLE':
                logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
                return 0
            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # connection = cx_Oracle.connect(
            #     user=db['db_user'], 
            #     password=db['db_password'],
            #     dsn=dsn, 
            #     mode=cx_Oracle.SYSDBA
            # )
            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )
            logger.info(f"Connected to {db['db_name']} as {db['db_user']} (SYSDBA)")

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM(
                            SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
                            FROM V$SESSION
                            WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'DCWATER_EXCHANGE'
                        )
                        """
                    )
                    result = cursor.fetchone()

            if result and result[0] > 0:
                active_users_count = result[0]
                logger.info(f"Count of active users in DCWATER_EXCHANGE: {active_users_count}")
                return active_users_count
            else:
                logger.warning(f"No active users found in schema 'DCWATER_EXCHANGE'.")
                return 0

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return 0
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return 0

    # def get_active_users_for_entergy_exchange(self, db):
    #     """Fetch active users for ENTERGY_EXCHANGE schema."""
    #     try:
    #         db_status = self.get_database_status()

    #         if db_status != 'AVAILABLE':
    #             logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
    #             return 0

    #         dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

    #         # connection = cx_Oracle.connect(
    #         #     user=db['db_user'], 
    #         #     password=db['db_password'],
    #         #     dsn=dsn, 
    #         #     mode=cx_Oracle.SYSDBA
    #         # )
    #         connection = cx_Oracle.connect(
    #             user=db['db_user'], 
    #             password=db['db_password'],
    #             dsn=dsn
    #         )
    #         logger.info(f"Connected to {db['db_name']} as {db['db_user']} (SYSDBA)")

    #         with connection:
    #             with connection.cursor() as cursor:
    #                 cursor.execute(
    #                     """
    #                     SELECT COUNT(*)
    #                     FROM(
    #                         SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
    #                         FROM V$SESSION
    #                         WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'ENTERGY_EXCHANGE'
    #                     )
    #                     """
    #                 )
    #                 result = cursor.fetchone()

    #         if result and result[0] > 0:
    #             active_users_count = result[0]
    #             logger.info(f"Count of active users in ENTERGY_EXCHANGE: {active_users_count}")
    #             return active_users_count
    #         else:
    #             logger.warning(f"No active users found in schema 'ENTERGY_EXCHANGE'.")
    #             return 0

    #     except cx_Oracle.DatabaseError as e:
    #         logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
    #         self._log_exception()
    #         return 0
    #     except Exception as e:
    #         logger.error(f"Unexpected error in monitoring script: {e}")
    #         self._log_exception()
    #         return 0
        
    def get_active_users_for_curaentergyproddx(self, db):
        """Fetch active users for CURAENTERGYPRODDX schema."""
        try:
            db_status = self.get_database_status()

            if db_status != 'AVAILABLE':
                logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
                return 0

            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # connection = cx_Oracle.connect(
            #     user=db['db_user'], 
            #     password=db['db_password'],
            #     dsn=dsn, 
            #     mode=cx_Oracle.SYSDBA
            # )
            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )
            logger.info(f"Connected to {db['db_name']} as {db['db_user']} (SYSDBA)")

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM(
                            SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
                            FROM V$SESSION
                            WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'CURAENTERGYPRODDX'
                        )
                        """
                    )
                    result = cursor.fetchone()

            if result and result[0] > 0:
                active_users_count = result[0]
                logger.info(f"Count of active users in CURAENTERGYPRODDX: {active_users_count}")
                return active_users_count
            else:
                logger.warning(f"No active users found in schema 'CURAENTERGYPRODDX'.")
                return 0

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return 0
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return 0

    def get_active_users_for_curaentergydx(self, db):
        """Fetch active users for CURAENTERGYDX schema."""
        try:
            db_status = self.get_database_status()

            if db_status != 'AVAILABLE':
                logger.warning(f"Active users data not available as the database '{db['db_name']}' is not active.")
                return 0

            dsn = cx_Oracle.makedsn(db['db_dsn'], db['db_port'], service_name=db['db_service_name'])

            # connection = cx_Oracle.connect(
            #     user=db['db_user'], 
            #     password=db['db_password'],
            #     dsn=dsn, 
            #     mode=cx_Oracle.SYSDBA
            # )
            connection = cx_Oracle.connect(
                user=db['db_user'],
                password=db['db_password'],
                dsn=dsn
            )
            logger.info(f"Connected to {db['db_name']} as {db['db_user']} (SYSDBA)")

            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM(
                            SELECT DISTINCT USERNAME, CON_ID, STATUS, SCHEMANAME, PROGRAM, MACHINE, OSUSER, LOGON_TIME, LAST_CALL_ET
                            FROM V$SESSION
                            WHERE USERNAME IS NOT NULL AND STATUS = 'ACTIVE' AND SCHEMANAME = 'CURAENTERGYDX'
                        )
                        """
                    )
                    result = cursor.fetchone()

            if result and result[0] > 0:
                active_users_count = result[0]
                logger.info(f"Count of active users in CURAENTERGYDX: {active_users_count}")
                return active_users_count
            else:
                logger.warning(f"No active users found in schema 'CURAENTERGYDX'.")
                return 0

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database Error for DB {db['db_name']} ({db['db_dsn']}): {e}")
            self._log_exception()
            return 0
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()
            return 0

    def update_active_users_metric_for_all_schemas(self):
        """Fetch and update the active user metrics for all schemas."""
        sys_dbs = [db for db in self.db_list if db['db_user'].upper() == 'C##READONLY']

        for db in sys_dbs:
            # Get active users for each schema
            entergy_cura_stage_users = self.get_active_users_for_entergy_cura_stage(db)
            self._print_blank_line()
            entergy_cura_prod_users = self.get_active_users_for_entergy_cura_prod(db)
            self._print_blank_line()
            dcwater_exchange_users = self.get_active_users_for_dcwater_exchange(db)
            self._print_blank_line()
            # entergy_exchange_users = self.get_active_users_for_entergy_exchange(db)
            # self._print_blank_line()
            curaentergyproddx_users = self.get_active_users_for_curaentergyproddx(db)
            self._print_blank_line()
            curaentergydx_users = self.get_active_users_for_curaentergydx(db)

            # Update Prometheus metrics for each schema
            self.metrics['db_active_users'].labels(db_id=self.db_id, schema="ENTERGY_CURA_STAGE").set(entergy_cura_stage_users)
            self.metrics['db_active_users'].labels(db_id=self.db_id, schema="ENTERGY_CURA_PROD").set(entergy_cura_prod_users)
            self.metrics['db_active_users'].labels(db_id=self.db_id, schema="DCWATER_EXCHANGE").set(dcwater_exchange_users)
            # self.metrics['db_active_users'].labels(db_id=self.db_id, schema="ENTERGY_EXCHANGE").set(entergy_exchange_users)
            self.metrics['db_active_users'].labels(db_id=self.db_id, schema="CURAENTERGYPRODDX").set(curaentergyproddx_users)
            self.metrics['db_active_users'].labels(db_id=self.db_id, schema="CURAENTERGYDX").set(curaentergydx_users)

    def run(self):
        """Main loop to perform monitoring tasks and handle server operations."""
        start_http_server(8000)
        logger.info("Prometheus server started at port 8000.")
        self._print_blank_line()

        try:
            while True:
                self.show_active_cx_users_count()

                self._print_blank_line()

                self.get_dcw_cx_latest_patch_version()

                self._print_blank_line()

                self.update_password_expiry_metric()

                self.update_tablespace_metrics()
                self._print_blank_line()

                self.update_active_users_metric_for_all_schemas()

                self._print_blank_line()

                # self.get_entergy_cx_latest_patch_version()

                # self._print_blank_line()

                self.get_instance_metrics()

                self.get_database_metrics()

                self.get_load_balancer_health()

                self._print_blank_line()

                time.sleep(0.5)

                self.get_backend_set_health()

                self._print_blank_line()

        except KeyboardInterrupt:
            logger.info("Monitoring script interrupted by user.")
        except Exception as e:
            logger.error(f"Unexpected error in monitoring script: {e}")
            self._log_exception()

if __name__ == "__main__":
    monitoring = MonitoringOCI()
    monitoring.run()