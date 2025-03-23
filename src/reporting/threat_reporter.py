# src/reporting/threat_reporter.py
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import jinja2
import pdfkit
import json

class ThreatReporter:
    """Generate detailed reports on detected threats and anomalies."""
   
    def __init__(self, output_dir="../data/reports"):
        """Initialize the ThreatReporter."""
        self.output_dir = output_dir
       
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
       
        # Set up Jinja2 environment for report templates
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader("templates")
        )
   
    def generate_summary_report(self, alerts_df, start_time=None, end_time=None, output_format="pdf"):
        """
        Generate a summary report of detected threats.
       
        Args:
            alerts_df: DataFrame containing alert data
            start_time: Start of reporting period
            end_time: End of reporting period
            output_format: "pdf", "html", or "json"
           
        Returns:
            str: Path to the generated report
        """
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_name = f"threat_summary_{timestamp}"
       
        # Process the alerts data
        summary_data = self._process_alert_data(alerts_df, start_time, end_time)
       
        if output_format == "pdf" or output_format == "html":
            # Render the HTML template
            template = self.jinja_env.get_template("summary_report.html")
            html_content = template.render(
                report_title="Network Threat Summary Report",
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                summary=summary_data
            )
           
            # Save as HTML first
            html_path = os.path.join(self.output_dir, f"{report_name}.html")
            with open(html_path, "w") as f:
                f.write(html_content)
           
            if output_format == "pdf":
                # Convert to PDF
                pdf_path = os.path.join(self.output_dir, f"{report_name}.pdf")
                pdfkit.from_file(html_path, pdf_path)
                return pdf_path
            return html_path
       
        elif output_format == "json":
            # Save as JSON
            json_path = os.path.join(self.output_dir, f"{report_name}.json")
            with open(json_path, "w") as f:
                json.dump(summary_data, f, indent=2)
            return json_path
   
    def _process_alert_data(self, alerts_df, start_time=None, end_time=None):
        """Process alert data to extract summary information."""
        # Filter by time range if specified
        if start_time:
            alerts_df = alerts_df[alerts_df['timestamp'] >= start_time]
        if end_time:
            alerts_df = alerts_df[alerts_df['timestamp'] <= end_time]
       
        # Calculate summary statistics
        total_alerts = len(alerts_df)
        severity_counts = alerts_df['severity'].value_counts().to_dict()
       
        # Group by source IP to find top attackers
        if 'src_ip' in alerts_df.columns:
            top_sources = alerts_df['src_ip'].value_counts().head(10).to_dict()
        else:
            top_sources = {}
       
        # Group by alert type
        alert_types = alerts_df['type'].value_counts().to_dict() if 'type' in alerts_df.columns else {}
       
        # Prepare summary data
        return {
            "total_alerts": total_alerts,
            "severity_distribution": severity_counts,
            "top_sources": top_sources,
            "alert_types": alert_types,
            "time_range": {
                "start": alerts_df['timestamp'].min() if not alerts_df.empty else None,
                "end": alerts_df['timestamp'].max() if not alerts_df.empty else None
            }
        }
   
    def generate_detailed_report(self, alert_id, alert_data, traffic_data=None, output_format="pdf"):
        """
        Generate a detailed report for a specific alert.
       
        Args:
            alert_id: ID of the alert
            alert_data: Dict containing alert details
            traffic_data: Associated traffic data (optional)
            output_format: "pdf", "html", or "json"
           
        Returns:
            str: Path to the generated report
        """
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_name = f"alert_details_{alert_id}_{timestamp}"
       
        # Prepare the report data
        report_data = {
            "alert_id": alert_id,
            "alert": alert_data,
            "traffic": traffic_data,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
       
        if output_format == "pdf" or output_format == "html":
            # Render the HTML template
            template = self.jinja_env.get_template("detailed_report.html")
            html_content = template.render(**report_data)
           
            # Save as HTML first
            html_path = os.path.join(self.output_dir, f"{report_name}.html")
            with open(html_path, "w") as f:
                f.write(html_content)
           
            if output_format == "pdf":
                # Convert to PDF
                pdf_path = os.path.join(self.output_dir, f"{report_name}.pdf")
                pdfkit.from_file(html_path, pdf_path)
                return pdf_path
            return html_path
       
        elif output_format == "json":
            # Save as JSON
            json_path = os.path.join(self.output_dir, f"{report_name}.json")
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2)
            return json_path