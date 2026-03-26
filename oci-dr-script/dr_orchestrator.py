"""
DR Orchestrator (copy of test_for_multi_instance.py)

Handles automatic failover between primary and standby instances
for multiple OCI environments.
"""

# Standard Library Imports
import json
import logging
import sys
import os
import smtplib
import re
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-Party Imports
import oci
from cryptography.fernet import Fernet, InvalidToken

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class DisasterRecovery:
    """Class to manage disaster recovery operations for OCI instances."""

    def __init__(self, config_file='config.json'):
        """Initialize the DisasterRecovery object."""
        self.config = self._load_config(config_file)
        
        if not self.config:
            raise ValueError("Failed to load and validate OCI configuration.")
        
        # Initialize OCI clients
        self.compute_client = oci.core.ComputeClient(config=self.config['oci'])
        self.load_balancer_client = oci.load_balancer.LoadBalancerClient(config=self.config['oci'])

        # Extract configuration data
        self.instances = self.config['instances']
        self.load_balancer_id = self.config['load_balancer']['id']
        self.load_balancer_name = self.config['load_balancer']['name']
        self.tenancy_id = self.config['oci']['tenancy']

        # Initialize email configuration
        self.email_config = {
            'sender_email_key': self.config['email']['sender_email_key'].encode(),
            'sender_email_encrypted_string': self.config['email']['sender_email_encrypted_string'].encode(),
            'smtp_server_key': self.config['email']['smtp_server_key'].encode(),
            'smtp_server_encrypted_string': self.config['email']['smtp_server_encrypted_string'].encode(),
            'smtp_password_key': self.config['email']['smtp_password_key'].encode(),
            'smtp_password_encrypted_string': self.config['email']['smtp_password_encrypted_string'].encode(),
            'smtp_username_key': self.config['email']['smtp_username_key'].encode(),
            'smtp_username_encrypted_string': self.config['email']['smtp_username_encrypted_string'].encode(),
            'smtp_port': self.config['email']['smtp_port'],
            'receiver_email_list': self.config['email']['receiver_email_list']
        }

    def _load_config(self, file_path='config.json'):
        """Load configuration from a JSON file and validate it."""
        try:
            with open(file_path, 'r') as file:
                config = json.load(file)
            
            # Validate main configuration sections
            required_sections = ['oci', 'email', 'instances', 'load_balancer']
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
            if not isinstance(config['instances'], list) or not all(isinstance(i, dict) for i in config['instances']):
                logger.error("Invalid 'instances' configuration: must be a list of dictionaries.")
                return None

            # Validate instance data
            required_instance_keys = [
                'primary_id', 'standby_id', 'primary_name', 'standby_name', 
                'ui_backend_set_name', 'api_backend_set_name'
            ]
            for instance in config.get('instances', []):
                missing_instance_keys = [key for key in required_instance_keys if key not in instance]
                if missing_instance_keys:
                    logger.error(f"Missing instance configuration keys: {missing_instance_keys}")
                    return None

                # Log the instance details
                logger.info(f"Instance initialized: {instance}")
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
        """Log exception details."""
        exc_type, exc_obj, exc_tb = sys.exc_info()
        if exc_type:
            # Extract filename and line number from traceback
            fname = os.path.basename(exc_tb.tb_frame.f_code.co_filename)
            lineno = exc_tb.tb_lineno
            # Log exception details
            logger.error(f"Exception type: {exc_type.__name__}, File: {fname}, Line: {lineno}")

    def _decrypt_string(self, key, encrypted_string):
        """Decrypt an encrypted string using a given key."""
        try:
            cipher_suite = Fernet(key)
            decrypted_string = cipher_suite.decrypt(encrypted_string).decode()
            return decrypted_string
        except (InvalidToken, ValueError) as e:
            logger.error(f"Decryption failed: {e}")
            self._log_exception()
            return None

    def _is_valid_email(self, email):
        """Utility function to validate email addresses."""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        try:
            return re.match(email_regex, email) is not None
        except re.error as e:
            logger.error(f"Regex error while validating email '{email}': {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while validating email '{email}': {e}")
            return False

    def send_email(self, receiver_email_list, subject, message, alert_type):
        """Send an email with the given subject and message to the receiver list."""
        if not isinstance(receiver_email_list, list):
            receiver_email_list = [receiver_email_list]

        # Decrypt email credentials and server info
        try:
            email_body = MIMEText(message, 'plain')
            sender_email = self._decrypt_string(
                self.email_config['sender_email_key'],
                self.email_config['sender_email_encrypted_string']
            )
            smtp_server = self._decrypt_string(
                self.email_config['smtp_server_key'],
                self.email_config['smtp_server_encrypted_string']
            )
            smtp_username = self._decrypt_string(
                self.email_config['smtp_username_key'],
                self.email_config['smtp_username_encrypted_string']
            )
            smtp_password = self._decrypt_string(
                self.email_config['smtp_password_key'],
                self.email_config['smtp_password_encrypted_string']
            )

            # Send email
            valid_email_count = 0
            with smtplib.SMTP(smtp_server, self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                for receiver_email in receiver_email_list:
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
            else:
                logger.info(f"No valid email addresses to send {alert_type} emails.")

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication Error: {e}")
            self._log_exception()
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection Error: {e}")
            self._log_exception()
        except smtplib.SMTPException as e:
            logger.error(f"SMTP Error: {e}")
            self._log_exception()
        except Exception as e:
            logger.error(f"An error occurred while sending email: {e}")
            self._log_exception()

    def notify_failover_activated(self, instance):
        """Notify that the failover has been activated for a specific instance."""
        primary_name = instance['primary_name']
        standby_name = instance['standby_name']
        subject = "Urgent: Primary Instance Down, Failover Activated"
        message = f"The primary instance '{primary_name}' has encountered an issue and is currently down. Failover has been initiated, and traffic has been redirected to the standby instance '{standby_name}'."
        self.send_email(self.email_config['receiver_email_list'], subject, message, 'Failover activation')

    def notify_failover_resolved(self, instance):
        """Notify that the failover has been resolved and the primary instance is restored."""
        primary_name = instance['primary_name']
        standby_name = instance['standby_name']
        subject = "Failover Resolved: Primary Instance Restored"
        message = f"Primary instance '{primary_name}' is now up. Traffic has been moved back, and the standby instance '{standby_name}' has been stopped."
        self.send_email(self.email_config['receiver_email_list'], subject, message, 'Failover resolution')

    def get_instance_status(self, instance_id):
        """Function to get the status of a specified instance."""
        try:
            # Fetch instance details
            instance = self.compute_client.get_instance(instance_id)
            return instance.data.lifecycle_state
        
        except oci.exceptions.ServiceError as e:
            logger.error(f"Error retrieving status for instance {instance_id}: {e}")
            self._log_exception()
            return None
        except Exception as ex:
            logger.error(f"Unexpected error occurred while retrieving status for instance {instance_id}: {ex}")
            self._log_exception()
            return None

    def get_instance_private_ip(self, instance_id):
        """Function to get the private IP address of a specified instance."""
        try:
            vnics = self.compute_client.list_vnic_attachments(self.tenancy_id, instance_id=instance_id).data
            if vnics:
                vnic = vnics[0]
                vnic_details = oci.core.VirtualNetworkClient(self.config['oci']).get_vnic(vnic.vnic_id).data
                return vnic_details.private_ip
            return None
        except oci.exceptions.ServiceError as e:
            logger.error(f"Error retrieving private IP for instance {instance_id}: {e}")
            self._log_exception()
            return None

    def start_standby_instance(self, instance_id):
        """Function to start the standby instance and wait until it is running."""
        timeout_seconds = 300
        retry_interval = 10
        max_retries = 5
        retries = 0

        # Find the standby name for the current instance_id
        instance_name = next(
            (item['standby_name'] for item in self.instances if item['standby_id'] == instance_id),
            'Unknown'
        )

        while retries < max_retries:
            try:
                self.compute_client.instance_action(instance_id, 'START')

                start_time = time.time()
                while True:
                    status = self.get_instance_status(instance_id)
                    if status == "RUNNING":
                        logger.info(f"Standby instance '{instance_name}' is now running.")
                        return

                    elapsed_time = time.time() - start_time
                    if elapsed_time >= timeout_seconds:
                        logger.error(f"Standby instance '{instance_name}' did not start within {timeout_seconds} seconds.")
                        return

                    time.sleep(10)

            except oci.exceptions.ServiceError as e:
                if e.status == 409:
                    retries += 1
                    logger.warning(f"Conflict error while starting standby instance '{instance_name}'. Retrying {retries}/{max_retries}...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Error starting standby instance '{instance_name}': {e}")
                    self._log_exception()
                    return

        logger.error(f"Max retries reached. Failed to start standby instance '{instance_name}'.")

    def stop_standby_instance(self, instance_id):
        """Function to stop the standby instance and wait until it is stopped."""
        timeout_seconds = 300
        retry_interval = 10
        max_retries = 5
        retries = 0

        # Find the standby name for the current instance_id
        instance_name = next(
            (item['standby_name'] for item in self.instances if item['standby_id'] == instance_id),
            'Unknown'
        )

        while retries < max_retries:
            try:
                self.compute_client.instance_action(instance_id, 'STOP')

                start_time = time.time()
                while True:
                    status = self.get_instance_status(instance_id)
                    if status == "STOPPED":
                        logger.info(f"Standby instance '{instance_name}' is now stopped.")
                        return

                    elapsed_time = time.time() - start_time
                    if elapsed_time >= timeout_seconds:
                        logger.error(f"Standby instance '{instance_name}' did not stop within {timeout_seconds} seconds.")
                        return

                    time.sleep(10)

            except oci.exceptions.ServiceError as e:
                if e.status == 409:
                    retries += 1
                    logger.warning(f"Conflict error while stopping standby instance '{instance_name}'. Retrying {retries}/{max_retries}...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Error stopping standby instance '{instance_name}': {e}")
                    self._log_exception()
                    return

        logger.error(f"Max retries reached. Failed to stop standby instance '{instance_name}'.")

    def get_health_checker_details(self, health_checker):
        """Function to convert health checker details to OCI Load Balancer model format."""
        return oci.load_balancer.models.HealthCheckerDetails(
            interval_in_millis=health_checker.interval_in_millis,
            is_force_plain_text=health_checker.is_force_plain_text,
            port=health_checker.port,
            protocol=health_checker.protocol,
            response_body_regex=health_checker.response_body_regex,
            retries=health_checker.retries,
            return_code=health_checker.return_code,
            timeout_in_millis=health_checker.timeout_in_millis,
            url_path=health_checker.url_path
        )

    def update_backend_set(self, backend_set_name, new_backend_instances, policy, health_checker):
        """Update the backend set of the load balancer with new instances."""
        try:
            # Get health checker details
            health_checker_details = self.get_health_checker_details(health_checker)

            # Prepare the list of backend details
            backend_details_list = [
                oci.load_balancer.models.BackendDetails(
                    ip_address=backend.ip_address,
                    port=backend.port,
                    weight=backend.weight,
                    backup=backend.backup,
                    drain=backend.drain,
                    offline=backend.offline
                ) for backend in new_backend_instances
            ]

            # Prepare the update backend set details object
            update_backend_set_details = oci.load_balancer.models.UpdateBackendSetDetails(
                backends=backend_details_list,
                policy=policy,
                health_checker=health_checker_details
            )

            # Update the backend set
            self.load_balancer_client.update_backend_set(
                load_balancer_id=self.load_balancer_id,
                backend_set_name=backend_set_name,
                update_backend_set_details=update_backend_set_details
            )

            logger.info(f"Backend set '{backend_set_name}' updated successfully.")

            # for backend in backend_details_list:
            #     logger.info(f"Backend set '{backend_set_name}' updated successfully with IP address '{backend.ip_address}'.")

        except oci.exceptions.ServiceError as e:
            logger.error(f"Error updating backend set '{backend_set_name}' for load balancer '{self.load_balancer_name}': {e}")
            self._log_exception()
        except Exception as ex:
            logger.error(f"Unexpected error occurred while updating backend set '{backend_set_name}': {ex}")
            self._log_exception()

    def switch_backend_sets_to_standby(self, instance):
        """Function to switch the backend sets to the standby instance during failover."""
        try:
            primary_id = instance['primary_id']
            standby_id = instance['standby_id']
            ui_backend_set_name = instance['ui_backend_set_name']
            api_backend_set_name = instance['api_backend_set_name']
            standby_name = instance['standby_name']

            primary_private_ip = self.get_instance_private_ip(primary_id)
            standby_private_ip = self.get_instance_private_ip(standby_id)

            # Update backend sets for UI
            backend_set_ui = self.load_balancer_client.get_backend_set(self.load_balancer_id, ui_backend_set_name).data
            new_backend_ui = oci.load_balancer.models.BackendDetails(ip_address=standby_private_ip, port=4200, weight=1)
            new_backend_instances_ui = [backend for backend in backend_set_ui.backends if backend.ip_address != primary_private_ip]
            new_backend_instances_ui.append(new_backend_ui)
            self.update_backend_set(ui_backend_set_name, new_backend_instances_ui, backend_set_ui.policy, backend_set_ui.health_checker)

            # Update backend sets for API
            backend_set_api = self.load_balancer_client.get_backend_set(self.load_balancer_id, api_backend_set_name).data
            new_backend_api = oci.load_balancer.models.BackendDetails(ip_address=standby_private_ip, port=5000, weight=1)
            new_backend_instances_api = [backend for backend in backend_set_api.backends if backend.ip_address != primary_private_ip]
            new_backend_instances_api.append(new_backend_api)
            self.update_backend_set(api_backend_set_name, new_backend_instances_api, backend_set_api.policy, backend_set_api.health_checker)

        except ValueError as ve:
            logger.error(f"Configuration error: {ve}")
            raise
        except oci.exceptions.ServiceError as se:
            logger.error(f"OCI service error: {se}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")
            self._log_exception()
            raise

    def switch_backend_sets_to_primary(self, instance):
        """Switch the backend sets to the primary instance."""
        try:
            primary_id = instance['primary_id']
            standby_id = instance['standby_id']
            ui_backend_set_name = instance['ui_backend_set_name']
            api_backend_set_name = instance['api_backend_set_name']
            primary_name = instance['primary_name']

            primary_private_ip = self.get_instance_private_ip(primary_id)
            standby_private_ip = self.get_instance_private_ip(standby_id)

            # Update backend sets for UI
            backend_set_ui = self.load_balancer_client.get_backend_set(self.load_balancer_id, ui_backend_set_name).data
            new_backend_ui = oci.load_balancer.models.BackendDetails(ip_address=primary_private_ip, port=4200, weight=1)
            new_backend_instances_ui = [backend for backend in backend_set_ui.backends if backend.ip_address != standby_private_ip]
            new_backend_instances_ui.append(new_backend_ui)
            self.update_backend_set(ui_backend_set_name, new_backend_instances_ui, backend_set_ui.policy, backend_set_ui.health_checker)

            # Update backend sets for API
            backend_set_api = self.load_balancer_client.get_backend_set(self.load_balancer_id, api_backend_set_name).data
            new_backend_api = oci.load_balancer.models.BackendDetails(ip_address=primary_private_ip, port=5000, weight=1)
            new_backend_instances_api = [backend for backend in backend_set_api.backends if backend.ip_address != standby_private_ip]
            new_backend_instances_api.append(new_backend_api)
            self.update_backend_set(api_backend_set_name, new_backend_instances_api, backend_set_api.policy, backend_set_api.health_checker)

        except ValueError as ve:
            logger.error(f"Configuration error: {ve}")
            raise
        except oci.exceptions.ServiceError as se:
            logger.error(f"OCI service error: {se}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")
            self._log_exception()
            raise

    def manage_failover(self):
        """Function to manage the failover process between primary and standby instances."""
        standby_started_flag = {instance['standby_id']: False for instance in self.instances}

        try:
            while True:
                for instance in self.instances:
                    primary_id = instance['primary_id']
                    standby_id = instance['standby_id']
                    primary_name = instance['primary_name']
                    standby_name = instance['standby_name']

                    primary_status = self.get_instance_status(primary_id)
                    standby_status = self.get_instance_status(standby_id)

                    if primary_status == "RUNNING":
                        if standby_status == "STOPPED":
                            logger.info(f"Primary instance '{primary_name}' is up. Monitoring...")
                            standby_started_flag[standby_id] = False
                        elif standby_status == "RUNNING":
                            logger.info(f"Primary instance '{primary_name}' is now up. Stopping standby instance '{standby_name}' and redirecting traffic back...")
                            self.stop_standby_instance(standby_id)
                            standby_started_flag[standby_id] = False
                            self.switch_backend_sets_to_primary(instance)
                            self.notify_failover_resolved(instance)
                        else:
                            logger.warning(f"Standby instance '{standby_name}' has unexpected status: {standby_status}. Waiting...")

                    elif primary_status == "STOPPED":
                        if standby_status == "RUNNING":
                            logger.info(f"Primary instance '{primary_name}' is still down. Standby instance '{standby_name}' is up and handling traffic.")
                        elif standby_status == "STOPPED":
                            if not standby_started_flag[standby_id]:
                                logger.info(f"Primary instance '{primary_name}' is down. Starting standby instance '{standby_name}' and redirecting traffic...")
                                self.start_standby_instance(standby_id)
                                standby_started_flag[standby_id] = True
                                self.switch_backend_sets_to_standby(instance)
                                self.notify_failover_activated(instance)
                            else:
                                logger.info(f"Both primary instance '{primary_name}' and standby instance '{standby_name}' are down. Immediate action required!")
                        else:
                            logger.warning(f"Standby instance '{standby_name}' has unexpected status: {standby_status}. Waiting...")

                    else:
                        logger.warning(f"Primary instance '{primary_name}' has unexpected status: {primary_status}. Waiting...")

                time.sleep(10)

        except KeyboardInterrupt:
            logger.info("Script terminated due to keyboard interruption.")

        except Exception as e:
            logger.error(f"An error occurred during failover management: {e}")
            self._log_exception()

def main():
    try:
        # Attempt to initialize the DisasterRecovery instance
        dr_instance = DisasterRecovery(config_file='config.json')
    except Exception as e:
        logger.error(f"Failed to initialize DisasterRecovery instance: {e}")
        sys.exit(1)

    try:
        # If initialization is successful, manage failover
        dr_instance.manage_failover()
    except Exception as e:
        logger.error(f"Failed to manage failover: {e}")
        dr_instance._log_exception()
        sys.exit(1)

if __name__ == "__main__":
    main()