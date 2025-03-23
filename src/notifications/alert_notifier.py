# src/notifications/alert_notifier.py
import os
import json
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import jinja2

class AlertNotifier:
    """Notification system for severe threat alerts."""
   
    def __init__(self, config_file=None):
        """Initialize AlertNotifier with configuration."""
        self.logger = logging.getLogger(__name__)
       
        # Default configuration
        self.config = {
            "email": {
                "enabled": False,
                "server": "smtp.gmail.com",
                "port": 587,
                "use_tls": True,
                "username": None,
                "password": None,
                "from_address": "alerts@example.com",
                "to_addresses": [],
                "severity_threshold": "high"
            },
            "slack": {
                "enabled": False,
                "webhook_url": None,
                "channel": "#security-alerts",
                "username": "AI Threat Detector",
                "severity_threshold": "medium"
            },
            "teams": {
                "enabled": False,
                "webhook_url": None,
                "severity_threshold": "high"
            }
        }
       
        # Load configuration if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
               
                # Update config recursively
                self._update_config_recursive(self.config, loaded_config)
               
                self.logger.info(f"Loaded notification configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Error loading notification configuration: {str(e)}")
       
        # Set up Jinja2 environment for notification templates
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader("templates/notifications")
        )
   
    def _update_config_recursive(self, target, source):
        """Update nested configuration dictionary recursively."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_config_recursive(target[key], value)
            else:
                target[key] = value
   
    def notify(self, alert):
        """
        Send notifications for an alert to all configured channels.
       
        Args:
            alert (dict): Alert data
           
        Returns:
            dict: Results of notification attempts
        """
        results = {}
        severity = alert.get("severity", "low").lower()
       
        # Email notification
        if self.config["email"]["enabled"]:
            if self._check_severity_threshold(severity, self.config["email"]["severity_threshold"]):
                results["email"] = self.send_email_notification(alert)
       
        # Slack notification
        if self.config["slack"]["enabled"]:
            if self._check_severity_threshold(severity, self.config["slack"]["severity_threshold"]):
                results["slack"] = self.send_slack_notification(alert)
       
        # Teams notification
        if self.config["teams"]["enabled"]:
            if self._check_severity_threshold(severity, self.config["teams"]["severity_threshold"]):
                results["teams"] = self.send_teams_notification(alert)
       
        return results
   
    def _check_severity_threshold(self, alert_severity, threshold):
        """Check if alert severity meets or exceeds the threshold."""
        severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
       
        alert_level = severity_levels.get(alert_severity, 0)
        threshold_level = severity_levels.get(threshold, 0)
       
        return alert_level >= threshold_level
   
    def send_email_notification(self, alert):
        """Send email notification for an alert."""
        try:
            config = self.config["email"]
           
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"Security Alert: {alert.get('type', 'Unknown Threat')} - {alert.get('severity', 'medium').upper()}"
            msg["From"] = config["from_address"]
            msg["To"] = ", ".join(config["to_addresses"])
           
            # Render email template
            template = self.jinja_env.get_template("email_alert.html")
            html_content = template.render(
                alert=alert,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
           
            # Create plain text and HTML versions
            text_part = MIMEText(f"Security Alert: {alert.get('description', 'Unknown Threat')}", "plain")
            html_part = MIMEText(html_content, "html")
           
            msg.attach(text_part)
            msg.attach(html_part)
           
            # Connect to SMTP server and send
            server = smtplib.SMTP(config["server"], config["port"])
            if config["use_tls"]:
                server.starttls()
           
            if config["username"] and config["password"]:
                server.login(config["username"], config["password"])
           
            server.sendmail(config["from_address"], config["to_addresses"], msg.as_string())
            server.quit()
           
            self.logger.info(f"Email notification sent for alert: {alert.get('type')}")
            return True
        except Exception as e:
            self.logger.error(f"Error sending email notification: {str(e)}")
            return False
   
    def send_slack_notification(self, alert):
        """Send Slack notification for an alert."""
        try:
            config = self.config["slack"]
           
            # Determine color based on severity
            color_map = {
                "low": "#36a64f",      # Green
                "medium": "#ffcc00",   # Yellow
                "high": "#ff9900",     # Orange
                "critical": "#ff0000"  # Red
            }
            color = color_map.get(alert.get("severity", "medium").lower(), "#ff9900")
           
            # Create Slack message payload
            payload = {
                "channel": config["channel"],
                "username": config["username"],
                "icon_emoji": ":rotating_light:",
                "attachments": [
                    {
                        "fallback": f"Security Alert: {alert.get('description', 'Unknown Threat')}",
                        "color": color,
                        "title": f"Security Alert: {alert.get('type', 'Unknown Threat')}",
                        "text": alert.get("description", "Unknown Threat"),
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.get("severity", "medium").upper(),
                                "short": True
                            },
                            {
                                "title": "Source",
                                "value": alert.get("source", "Unknown"),
                                "short": True
                            },
                            {
                                "title": "Time",
                                "value": alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                                "short": True
                            }
                        ],
                        "footer": "AI Threat Detection System",
                        "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
           
            # Add threat intelligence if available
            if "threat_intel" in alert:
                threat_intel = alert["threat_intel"]
               
                payload["attachments"][0]["fields"].append({
                    "title": "Risk Score",
                    "value": f"{threat_intel.get('risk_score', 0)}/100",
                    "short": True
                })
               
                if "categories" in threat_intel and threat_intel["categories"]:
                    payload["attachments"][0]["fields"].append({
                        "title": "Threat Categories",
                        "value": ", ".join(threat_intel["categories"]),
                        "short": False
                    })
           
            # Send to Slack webhook
            response = requests.post(
                config["webhook_url"],
                json=payload,
                headers={"Content-Type": "application/json"}
            )
           
            if response.status_code == 200:
                self.logger.info(f"Slack notification sent for alert: {alert.get('type')}")
                return True
            else:
                self.logger.error(f"Error sending Slack notification: {response.status_code} - {response.text}")
                return False
       
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {str(e)}")
            return False
   
    def send_teams_notification(self, alert):
        """Send Microsoft Teams notification for an alert."""
        try:
            config = self.config["teams"]
           
            # Determine color based on severity
            color_map = {
                "low": "008000",       # Green
                "medium": "FFC000",    # Yellow
                "high": "FF9900",      # Orange
                "critical": "FF0000"   # Red
            }
            theme_color = color_map.get(alert.get("severity", "medium").lower(), "FF9900")
           
            # Create Teams message payload
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": theme_color,
                "summary": f"Security Alert: {alert.get('type', 'Unknown Threat')}",
                "sections": [
                    {
                        "activityTitle": f"Security Alert: {alert.get('type', 'Unknown Threat')}",
                        "activitySubtitle": f"Severity: {alert.get('severity', 'medium').upper()}",
                        "activityImage": "https://img.icons8.com/color/48/000000/security-shield.png",
                        "facts": [
                            {
                                "name": "Description",
                                "value": alert.get("description", "Unknown Threat")
                            },
                            {
                                "name": "Source",
                                "value": alert.get("source", "Unknown")
                            },
                            {
                                "name": "Time",
                                "value": alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                            }
                        ],
                        "markdown": True
                    }
                ]
            }
           
            # Add threat intelligence if available
            if "threat_intel" in alert:
                threat_intel = alert["threat_intel"]
               
                intelligence_section = {
                    "title": "Threat Intelligence",
                    "facts": [
                        {
                            "name": "Risk Score",
                            "value": f"{threat_intel.get('risk_score', 0)}/100"
                        }
                    ]
                }
               
                if "categories" in threat_intel and threat_intel["categories"]:
                    intelligence_section["facts"].append({
                        "name": "Threat Categories",
                        "value": ", ".join(threat_intel["categories"])
                    })
               
                payload["sections"].append(intelligence_section)
           
            # Send to Teams webhook
            response = requests.post(
                config["webhook_url"],
                json=payload,
                headers={"Content-Type": "application/json"}
            )
           
            if response.status_code == 200:
                self.logger.info(f"Teams notification sent for alert: {alert.get('type')}")
                return True
            else:
                self.logger.error(f"Error sending Teams notification: {response.status_code} - {response.text}")
                return False
       
        except Exception as e:
            self.logger.error(f"Error sending Teams notification: {str(e)}")
            return False
