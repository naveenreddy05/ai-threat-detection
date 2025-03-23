# src/integration/siem_connector.py
import os
import json
import logging
import requests
from datetime import datetime

class SIEMConnector:
    """Connector for integration with SIEM systems."""
   
    def __init__(self, config_file=None):
        """Initialize SIEM connector with configuration."""
        self.logger = logging.getLogger(__name__)
       
        # Default configuration
        self.config = {
            "enabled": False,
            "siem_type": "generic",
            "url": None,
            "api_key": None,
            "auth_token": None,
            "auth_type": "none",
            "batch_size": 50,
            "timeout": 30
        }
       
        # Load configuration if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    self.config.update(json.load(f))
                self.logger.info(f"Loaded SIEM configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Error loading SIEM configuration: {str(e)}")
   
    def send_alert(self, alert_data):
        """
        Send a single alert to the SIEM system.
       
        Args:
            alert_data (dict): Alert data to send
           
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.config["enabled"] or not self.config["url"]:
            self.logger.warning("SIEM integration is not enabled or URL is not configured")
            return False
       
        # Format alert according to SIEM type
        formatted_alert = self._format_alert(alert_data)
       
        try:
            # Prepare request headers
            headers = self._get_auth_headers()
            headers.update({
                "Content-Type": "application/json"
            })
           
            # Send the alert to SIEM
            response = requests.post(
                self.config["url"],
                headers=headers,
                json=formatted_alert,
                timeout=self.config["timeout"]
            )
           
            if response.status_code >= 200 and response.status_code < 300:
                self.logger.info(f"Successfully sent alert to SIEM: {response.status_code}")
                return True
            else:
                self.logger.error(f"Failed to send alert to SIEM. Status: {response.status_code}, Response: {response.text}")
                return False
               
        except Exception as e:
            self.logger.error(f"Error sending alert to SIEM: {str(e)}")
            return False
   
    def send_alerts_batch(self, alerts):
        """
        Send multiple alerts to the SIEM system in batches.
       
        Args:
            alerts (list): List of alert dictionaries
           
        Returns:
            tuple: (success_count, failed_count)
        """
        if not self.config["enabled"] or not self.config["url"]:
            self.logger.warning("SIEM integration is not enabled or URL is not configured")
            return 0, len(alerts)
       
        success_count = 0
        failed_count = 0
        batch_size = self.config["batch_size"]
       
        # Process alerts in batches
        for i in range(0, len(alerts), batch_size):
            batch = alerts[i:i+batch_size]
           
            # Format all alerts in the batch
            formatted_batch = [self._format_alert(alert) for alert in batch]
           
            try:
                # Prepare request headers
                headers = self._get_auth_headers()
                headers.update({
                    "Content-Type": "application/json"
                })
               
                # Send the batch to SIEM
                response = requests.post(
                    self.config["url"],
                    headers=headers,
                    json=formatted_batch,
                    timeout=self.config["timeout"]
                )
               
                if response.status_code >= 200 and response.status_code < 300:
                    self.logger.info(f"Successfully sent batch of {len(batch)} alerts to SIEM")
                    success_count += len(batch)
                else:
                    self.logger.error(f"Failed to send batch to SIEM. Status: {response.status_code}")
                    failed_count += len(batch)
                   
            except Exception as e:
                self.logger.error(f"Error sending batch to SIEM: {str(e)}")
                failed_count += len(batch)
       
        return success_count, failed_count
   
    def _get_auth_headers(self):
        """Get authentication headers based on configured auth type."""
        headers = {}
       
        auth_type = self.config["auth_type"].lower()
       
        if auth_type == "api_key":
            headers["X-API-Key"] = self.config["api_key"]
        elif auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.config['auth_token']}"
        elif auth_type == "basic":
            # Note: In production, you should use a more secure method to store credentials
            import base64
            if "username" in self.config and "password" in self.config:
                auth_string = f"{self.config['username']}:{self.config['password']}"
                encoded = base64.b64encode(auth_string.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
       
        return headers
   
    def _format_alert(self, alert_data):
        """Format alert according to SIEM requirements."""
        siem_type = self.config["siem_type"].lower()
       
        if siem_type == "splunk":
            return self._format_for_splunk(alert_data)
        elif siem_type == "elastic":
            return self._format_for_elastic(alert_data)
        elif siem_type == "qradar":
            return self._format_for_qradar(alert_data)
        else:
            # Generic format
            return {
                "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
                "severity": alert_data.get("severity", "medium"),
                "type": alert_data.get("type", "Unknown"),
                "source": "AI-Threat-Detection",
                "details": alert_data
            }
   
    def _format_for_splunk(self, alert_data):
        """Format alert for Splunk HEC."""
        return {
            "time": int(datetime.now().timestamp()),
            "host": "ai-threat-detection",
            "source": "network-anomaly-detection",
            "sourcetype": "threat:detection",
            "index": "security",
            "event": alert_data
        }
   
    def _format_for_elastic(self, alert_data):
        """Format alert for Elasticsearch."""
        return {
            "@timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
            "message": f"Network threat detected: {alert_data.get('type', 'Unknown')}",
            "log": {
                "level": alert_data.get("severity", "medium")
            },
            "event": {
                "module": "threat_detection",
                "dataset": "network",
                "severity": alert_data.get("severity", 3),
                "action": "detected"
            },
            "host": {
                "name": "ai-threat-detection"
            },
            "network": {
                "protocol": alert_data.get("protocol", "unknown"),
                "source": {
                    "ip": alert_data.get("src_ip", "unknown")
                },
                "destination": {
                    "ip": alert_data.get("dst_ip", "unknown")
                }
            },
            "threat": {
                "framework": "AI-Detection",
                "indicator": alert_data
            }
        }
   
    def _format_for_qradar(self, alert_data):
        """Format alert for IBM QRadar."""
        return {
            "eventTime": int(datetime.now().timestamp() * 1000),
            "deviceVendor": "AI-Threat-Detection",
            "deviceProduct": "Network-Anomaly-Detector",
            "deviceVersion": "1.0",
            "category": "Security Intelligence",
            "severity": self._map_severity_to_qradar(alert_data.get("severity", "medium")),
            "name": f"Network anomaly detected: {alert_data.get('type', 'Unknown')}",
            "sourceAddress": alert_data.get("src_ip", "unknown"),
            "destinationAddress": alert_data.get("dst_ip", "unknown"),
            "protocol": alert_data.get("protocol", "unknown"),
            "customFields": alert_data
        }
   
    def _map_severity_to_qradar(self, severity):
        """Map severity string to QRadar severity level (1-10)."""
        severity_map = {
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10
        }
        return severity_map.get(severity.lower(), 5)
