# src/integration/threat_intelligence.py
import os
import json
import logging
import requests
import time
import hashlib
import ipaddress
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class ThreatIntelligence:
    """Integration with threat intelligence sources to enrich alerts with AI capabilities."""
   
    def __init__(self, config_file=None, cache_dir="../data/cache"):
        """Initialize ThreatIntelligence with configuration."""
        self.logger = logging.getLogger(__name__)
        self.cache_dir = cache_dir
       
        # Create cache directory if it doesn't exist
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
       
        # Default configuration
        self.config = {
            "enabled": False,
            "sources": [],
            "cache_duration": 86400,  # 24 hours in seconds
            "timeout": 10,
            'api_keys': {},
            'cache_expiry_days': 7,
            'confidence_threshold': 0.7
        }
       
        # Available intelligence sources
        self.available_sources = {
            "abuseipdb": {
                "enabled": False,
                "api_key": None,
                "base_url": "https://api.abuseipdb.com/api/v2/check",
                "headers": {"Accept": "application/json"}
            },
            "virustotal": {
                "enabled": False,
                "api_key": None,
                "base_url": "https://www.virustotal.com/api/v3/ip_addresses/{}",
                "headers": {"Accept": "application/json"}
            },
            "ipqualityscore": {
                "enabled": False,
                "api_key": None,
                "base_url": "https://ipqualityscore.com/api/json/ip/{}",
                "headers": {"Accept": "application/json"}
            },
            "local_blocklist": {
                "enabled": True,
                "file_path": "../data/blocklists/ip_blocklist.txt",
                "update_interval": 86400  # 24 hours in seconds
            },
            "local_cache": {
                "enabled": True
            },
            "api": {
                "enabled": True
            }
        }
       
        # Load configuration if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
               
                # Update main config
                for key, value in loaded_config.items():
                    if key != "sources":
                        self.config[key] = value
               
                # Update sources config
                if "sources" in loaded_config:
                    for source, source_config in loaded_config["sources"].items():
                        if source in self.available_sources:
                            self.available_sources[source].update(source_config)
                            # Add to active sources if enabled
                            if source_config.get("enabled", False):
                                self.config["sources"].append(source)
               
                self.logger.info(f"Loaded threat intelligence configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Error loading threat intelligence configuration: {str(e)}")
       
        # Initialize local blocklists
        self._init_local_blocklists()
       
        # Initialize threat database (simple for demo)
        self.threat_db = self._load_threat_database()
       
        # Initialize AI components for threat analysis
        self.initialize_ai_components()
   
    def _init_local_blocklists(self):
        """Initialize local blocklists."""
        self.blocklists = {
            "ip": set()
        }
       
        # Load local IP blocklist if enabled
        if self.available_sources["local_blocklist"]["enabled"]:
            blocklist_path = self.available_sources["local_blocklist"]["file_path"]
            if os.path.exists(blocklist_path):
                try:
                    with open(blocklist_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                self.blocklists["ip"].add(line)
                    self.logger.info(f"Loaded {len(self.blocklists['ip'])} IPs from local blocklist")
                except Exception as e:
                    self.logger.error(f"Error loading local IP blocklist: {str(e)}")
   
    def initialize_ai_components(self):
        """Initialize AI components for enhanced threat analysis."""
        # TF-IDF vectorizer for analyzing threat descriptions
        self.tfidf = TfidfVectorizer(max_features=1000, stop_words='english')
       
        # If we have threat data, fit the vectorizer
        if hasattr(self, 'threat_db') and self.threat_db is not None and not self.threat_db.empty and 'description' in self.threat_db.columns:
            descriptions = self.threat_db['description'].fillna('')
            try:
                self.tfidf.fit(descriptions)
                # Create a matrix of vectorized descriptions
                self.threat_vectors = self.tfidf.transform(descriptions)
            except Exception as e:
                self.logger.error(f"Error initializing TF-IDF vectorizer: {str(e)}")
   
    def _load_threat_database(self):
        """Load threat intelligence database from cache."""
        cache_file = os.path.join(self.cache_dir, "threat_database.csv")
       
        if os.path.exists(cache_file):
            try:
                return pd.read_csv(cache_file)
            except Exception as e:
                self.logger.error(f"Error loading threat database: {str(e)}")
       
        # Create empty database if none exists
        return pd.DataFrame(columns=[
            'indicator', 'type', 'confidence', 'severity',
            'description', 'tags', 'last_seen', 'source'
        ])
   
    def enrich_ip(self, ip_address):
        """
        Enrich data about an IP address with threat intelligence.
       
        Args:
            ip_address (str): IP address to check
           
        Returns:
            dict: Enriched data about the IP
        """
        if not self.config["enabled"]:
            return {"ip": ip_address, "enriched": False}
       
        # Check cache first
        cache_result = self._check_cache("ip", ip_address)
        if cache_result:
            return cache_result
       
        # Prepare result structure
        result = {
            "ip": ip_address,
            "enriched": True,
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "is_malicious": False,
            "risk_score": 0,
            "categories": [],
            "location": {}
        }
       
        # Check local blocklist first
        if self.available_sources["local_blocklist"]["enabled"]:
            if ip_address in self.blocklists["ip"]:
                result["is_malicious"] = True
                result["risk_score"] = 100
                result["categories"].append("local_blocklist")
                result["sources"]["local_blocklist"] = {
                    "found": True,
                    "score": 100
                }
       
        # Query enabled external sources
        for source in self.config["sources"]:
            if source in self.available_sources and self.available_sources[source]["enabled"]:
                source_result = self._query_source(source, "ip", ip_address)
                if source_result:
                    result["sources"][source] = source_result
                   
                    # Update overall risk assessment
                    if source_result.get("is_malicious", False):
                        result["is_malicious"] = True
                   
                    # Update risk score (take max of all sources)
                    result["risk_score"] = max(result["risk_score"], source_result.get("score", 0))
                   
                    # Add categories
                    if "categories" in source_result:
                        result["categories"].extend(source_result["categories"])
                   
                    # Add location data if available
                    if "location" in source_result:
                        result["location"] = source_result["location"]
       
        # Deduplicate categories
        result["categories"] = list(set(result["categories"]))
       
        # Cache the result
        self._cache_result("ip", ip_address, result)
       
        return result
   
    def _query_source(self, source, entity_type, entity_value):
        """Query a specific intelligence source for information."""
        source_config = self.available_sources[source]
       
        # For local blocklist, we already checked
        if source == "local_blocklist" or source == "local_cache" or source == "api":
            return None
       
        try:
            if source == "abuseipdb" and entity_type == "ip":
                return self._query_abuseipdb(entity_value)
            elif source == "virustotal" and entity_type == "ip":
                return self._query_virustotal(entity_value)
            elif source == "ipqualityscore" and entity_type == "ip":
                return self._query_ipqualityscore(entity_value)
        except Exception as e:
            self.logger.error(f"Error querying {source} for {entity_type} {entity_value}: {str(e)}")
       
        return None
   
    def _query_abuseipdb(self, ip):
        """Query AbuseIPDB for IP reputation."""
        source_config = self.available_sources["abuseipdb"]
        if not source_config["api_key"]:
            return None
       
        headers = source_config["headers"].copy()
        headers["Key"] = source_config["api_key"]
       
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
       
        response = requests.get(
            source_config["base_url"],
            headers=headers,
            params=params,
            timeout=self.config["timeout"]
        )
       
        if response.status_code == 200:
            data = response.json().get("data", {})
           
            # Extract useful information
            result = {
                "score": data.get("abuseConfidenceScore", 0),
                "is_malicious": data.get("abuseConfidenceScore", 0) > 50,
                "categories": [],
                "location": {
                    "country": data.get("countryCode"),
                    "isp": data.get("isp")
                },
                "last_reported": data.get("lastReportedAt")
            }
           
            # Convert category codes to names
            categories = data.get("reports", [])
            category_map = {
                1: "dns_compromise",
                2: "dns_poisoning",
                3: "fraud_orders",
                4: "ddos_attack",
                5: "ftp_brute_force",
                6: "ping_of_death",
                7: "phishing",
                8: "fraud_voip",
                9: "open_proxy",
                10: "web_spam",
                11: "email_spam",
                12: "blog_spam",
                13: "vpn_ip",
                14: "port_scan",
                15: "hacking",
                16: "sql_injection",
                17: "spoofing",
                18: "brute_force",
                19: "bad_web_bot",
                20: "exploited_host",
                21: "web_app_attack",
                22: "ssh",
                23: "iot_targeted"
            }
           
            for report in categories:
                for cat in report.get("categories", []):
                    if cat in category_map:
                        result["categories"].append(category_map[cat])
           
            return result
       
        return None
   
    def _query_virustotal(self, ip):
        """Query VirusTotal for IP reputation."""
        source_config = self.available_sources["virustotal"]
        if not source_config["api_key"]:
            return None
       
        headers = source_config["headers"].copy()
        headers["x-apikey"] = source_config["api_key"]
       
        url = source_config["base_url"].format(ip)
       
        response = requests.get(
            url,
            headers=headers,
            timeout=self.config["timeout"]
        )
       
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
           
            # Calculate malicious score based on security vendors' assessments
            last_analysis = attributes.get("last_analysis_stats", {})
            malicious_count = last_analysis.get("malicious", 0)
            suspicious_count = last_analysis.get("suspicious", 0)
            total_count = sum(last_analysis.values())
           
            score = 0
            if total_count > 0:
                score = int(((malicious_count * 1.0) + (suspicious_count * 0.5)) / total_count * 100)
           
            # Extract categories/tags
            categories = []
            for category in attributes.get("categories", {}).values():
                categories.append(category.lower().replace(" ", "_"))
           
            # Get location data
            location = {}
            if "country" in attributes:
                location["country"] = attributes["country"]
            if "as_owner" in attributes:
                location["isp"] = attributes["as_owner"]
           
            return {
                "score": score,
                "is_malicious": score > 50,
                "categories": categories,
                "location": location,
                "last_analysis_date": attributes.get("last_analysis_date")
            }
       
        return None
   
    def _query_ipqualityscore(self, ip):
        """Query IPQualityScore for IP reputation."""
        source_config = self.available_sources["ipqualityscore"]
        if not source_config["api_key"]:
            return None
       
        api_key = source_config["api_key"]
        url = f"{source_config['base_url'].format(api_key)}/{ip}"
       
        response = requests.get(
            url,
            headers=source_config["headers"],
            timeout=self.config["timeout"]
        )
       
        if response.status_code == 200:
            data = response.json()
           
            # Calculate overall score
            fraud_score = data.get("fraud_score", 0)
           
            # Determine categories
            categories = []
            if data.get("proxy", False):
                categories.append("proxy")
            if data.get("vpn", False):
                categories.append("vpn")
            if data.get("tor", False):
                categories.append("tor")
            if data.get("bot_status", False):
                categories.append("bot")
            if data.get("is_crawler", False):
                categories.append("crawler")
            if data.get("recent_abuse", False):
                categories.append("recent_abuse")
           
            # Location data
            location = {
                "country": data.get("country_code"),
                "city": data.get("city"),
                "region": data.get("region"),
                "isp": data.get("ISP")
            }
           
            return {
                "score": fraud_score,
                "is_malicious": fraud_score > 75,
                "categories": categories,
                "location": location
            }
       
        return None
   
    def _cache_key(self, entity_type, entity_value):
        """Generate a cache key for an entity."""
        return f"{entity_type}_{hashlib.md5(entity_value.encode()).hexdigest()}"
   
    def _check_cache(self, entity_type, entity_value):
        """Check if entity data is in cache and still valid."""
        cache_key = self._cache_key(entity_type, entity_value)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
       
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
               
                # Check if cache is still valid
                timestamp = datetime.fromisoformat(cached_data.get("timestamp", "2000-01-01T00:00:00"))
                cache_duration = self.config["cache_duration"]
               
                if (datetime.now() - timestamp).total_seconds() < cache_duration:
                    return cached_data
            except Exception as e:
                self.logger.error(f"Error reading cache: {str(e)}")
       
        return None
   
    def _cache_result(self, entity_type, entity_value, result):
        """Cache the result for an entity."""
        cache_key = self._cache_key(entity_type, entity_value)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
       
        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f)
        except Exception as e:
            self.logger.error(f"Error caching result: {str(e)}")
   
    def enrich_alert(self, alert):
        """Enrich an alert with threat intelligence."""
        if not self.config['enabled'] or self.threat_db.empty:
            return alert
       
        # Check for indicators in the alert
        indicators = self._extract_indicators(alert)
       
        # Look up each indicator
        matched_intel = []
        confidence_scores = []
       
        for indicator in indicators:
            intel, confidence = self._lookup_indicator(indicator)
            if intel is not None:
                matched_intel.append(intel)
                confidence_scores.append(confidence)
       
        # If we found intelligence, add it to the alert
        if matched_intel:
            # Sort by confidence and get the highest
            best_match_idx = np.argmax(confidence_scores)
            best_match = matched_intel[best_match_idx]
            best_confidence = confidence_scores[best_match_idx]
           
            # Add to alert
            alert['threat_confidence'] = float(best_confidence)
            alert['threat_severity'] = best_match.get('severity', 'unknown')
            alert['threat_description'] = best_match.get('description', '')
            alert['threat_tags'] = best_match.get('tags', '')
           
            # Format for display
            tags_str = best_match.get('tags', '').replace(',', ', ')
            alert['threat_intel_display'] = (
                f"**Risk: {int(best_confidence*100)}%** - {tags_str}"
            )
       
        return alert
   
    def _extract_indicators(self, alert):
        """Extract potential threat indicators from an alert."""
        indicators = []
       
        # Extract IPs
        if 'src_ip' in alert:
            indicators.append({'value': alert['src_ip'], 'type': 'ip'})
        if 'dst_ip' in alert:
            indicators.append({'value': alert['dst_ip'], 'type': 'ip'})
       
        # Could extract other indicators like domain names, file hashes, etc.
       
        return indicators
   
    def _lookup_indicator(self, indicator):
        """Look up an indicator in the threat database."""
        if self.threat_db.empty:
            return None, 0
       
        # Filter by indicator type and value
        matches = self.threat_db[
            (self.threat_db['indicator'] == indicator['value']) &
            (self.threat_db['type'] == indicator['type'])
        ]
       
        if not matches.empty:
            # Return the highest confidence match
            best_match = matches.loc[matches['confidence'].idxmax()]
            return best_match.to_dict(), best_match['confidence']
       
        return None, 0
   
    def analyze_anomalies(self, alerts_df, network_data=None):
        """Use AI to analyze anomalies and identify potential threats."""
        if not self.config['enabled'] or alerts_df.empty:
            return alerts_df
       
        # Extract alert descriptions
        if 'description' in alerts_df.columns:
            descriptions = alerts_df['description'].fillna('')
           
            # Vectorize the descriptions
            alert_vectors = self.tfidf.transform(descriptions)
           
            # Compare to known threat descriptions
            if hasattr(self, 'threat_vectors') and self.threat_vectors is not None:
                similarities = cosine_similarity(alert_vectors, self.threat_vectors)
               
                # Get the highest similarity score for each alert
                max_similarities = np.max(similarities, axis=1)
               
                # Get indices of the closest threat for each alert
                closest_threats = np.argmax(similarities, axis=1)
               
                # Add similarity and threat information to alerts
                alerts_df['threat_similarity'] = max_similarities
               
                # Add threat information for alerts above threshold
                for i, (idx, sim) in enumerate(zip(closest_threats, max_similarities)):
                    if sim > self.config['confidence_threshold']:
                        threat = self.threat_db.iloc[idx]
                        alerts_df.loc[alerts_df.index[i], 'threat_matched'] = True
                        alerts_df.loc[alerts_df.index[i], 'threat_type'] = threat.get('type', '')
                        alerts_df.loc[alerts_df.index[i], 'threat_tags'] = threat.get('tags', '')
                        alerts_df.loc[alerts_df.index[i], 'threat_severity'] = threat.get('severity', 'medium')
                        alerts_df.loc[alerts_df.index[i], 'threat_confidence'] = sim
       
        return alerts_df