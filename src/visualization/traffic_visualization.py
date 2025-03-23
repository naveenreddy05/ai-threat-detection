import os
import sys
import logging
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from datetime import datetime, timedelta

class TrafficVisualizer:
    """
    Class for visualizing network traffic data.
    """
    def __init__(self, output_dir="../data/results"):
        """
        Initialize TrafficVisualizer.
       
        Args:
            output_dir (str): Directory to save visualization outputs
        """
        self.output_dir = output_dir
       
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
           
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
   
    def plot_traffic_volume(self, df, time_col='timestamp', output_file=None, interactive=False):
        """
        Plot network traffic volume over time.
       
        Args:
            df (pandas.DataFrame): DataFrame with traffic data
            time_col (str): Column name for timestamp
            output_file (str): Filename for output visualization
            interactive (bool): Whether to create interactive plot
           
        Returns:
            str: Path to saved visualization file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_traffic_volume.{'html' if interactive else 'png'}"
           
        output_path = os.path.join(self.output_dir, output_file)
       
        try:
            # Ensure timestamp is datetime
            if df[time_col].dtype != 'datetime64[ns]':
                df = df.copy()
                df['datetime'] = pd.to_datetime(df[time_col], unit='s')
                time_col = 'datetime'
           
            # Resample data to different time intervals
            time_windows = {
                'minute': df.set_index(time_col).resample('1min').size(),
                '5minutes': df.set_index(time_col).resample('5min').size(),
                'hour': df.set_index(time_col).resample('1H').size()
            }
           
            if interactive:
                # Create interactive plot with Plotly
                fig = make_subplots(rows=3, cols=1,
                                    subplot_titles=('Traffic per Minute', 'Traffic per 5 Minutes', 'Traffic per Hour'),
                                    vertical_spacing=0.1)
               
                fig.add_trace(
                    go.Scatter(x=time_windows['minute'].index, y=time_windows['minute'].values,
                              mode='lines', name='Per Minute'),
                    row=1, col=1
                )
               
                fig.add_trace(
                    go.Scatter(x=time_windows['5minutes'].index, y=time_windows['5minutes'].values,
                              mode='lines', name='Per 5 Minutes'),
                    row=2, col=1
                )
               
                fig.add_trace(
                    go.Scatter(x=time_windows['hour'].index, y=time_windows['hour'].values,
                              mode='lines', name='Per Hour'),
                    row=3, col=1
                )
               
                fig.update_layout(
                    title='Network Traffic Volume Over Time',
                    height=900,
                    showlegend=False
                )
               
                fig.write_html(output_path)
            else:
                # Create static plot with Matplotlib
                plt.figure(figsize=(15, 10))
               
                plt.subplot(3, 1, 1)
                time_windows['minute'].plot()
                plt.title('Traffic per Minute')
                plt.ylabel('Packet Count')
               
                plt.subplot(3, 1, 2)
                time_windows['5minutes'].plot()
                plt.title('Traffic per 5 Minutes')
                plt.ylabel('Packet Count')
               
                plt.subplot(3, 1, 3)
                time_windows['hour'].plot()
                plt.title('Traffic per Hour')
                plt.ylabel('Packet Count')
               
                plt.tight_layout()
                plt.savefig(output_path)
                plt.close()
           
            self.logger.info(f"Saved traffic volume visualization to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing traffic volume: {str(e)}")
            return None
   
    def plot_protocol_distribution(self, df, protocol_col='protocol', output_file=None, interactive=False):
        """
        Plot distribution of network protocols.
       
        Args:
            df (pandas.DataFrame): DataFrame with traffic data
            protocol_col (str): Column name for protocol
            output_file (str): Filename for output visualization
            interactive (bool): Whether to create interactive plot
           
        Returns:
            str: Path to saved visualization file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_protocol_dist.{'html' if interactive else 'png'}"
           
        output_path = os.path.join(self.output_dir, output_file)
       
        try:
            # Count protocols
            protocol_counts = df[protocol_col].value_counts()
           
            if interactive:
                # Create interactive plot with Plotly
                fig = make_subplots(rows=1, cols=2,
                                    specs=[[{"type": "pie"}, {"type": "bar"}]],
                                    subplot_titles=('Protocol Distribution (Pie)', 'Protocol Distribution (Bar)'))
               
                fig.add_trace(
                    go.Pie(labels=protocol_counts.index, values=protocol_counts.values,
                          textinfo='percent+label'),
                    row=1, col=1
                )
               
                fig.add_trace(
                    go.Bar(x=protocol_counts.index, y=protocol_counts.values),
                    row=1, col=2
                )
               
                fig.update_layout(
                    title='Network Protocol Distribution',
                    height=500
                )
               
                fig.write_html(output_path)
            else:
                # Create static plot with Matplotlib
                plt.figure(figsize=(15, 6))
               
                plt.subplot(1, 2, 1)
                plt.pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%')
                plt.title('Protocol Distribution (Pie)')
               
                plt.subplot(1, 2, 2)
                sns.barplot(x=protocol_counts.index, y=protocol_counts.values)
                plt.title('Protocol Distribution (Bar)')
                plt.ylabel('Count')
                plt.xticks(rotation=45)
               
                plt.tight_layout()
                plt.savefig(output_path)
                plt.close()
           
            self.logger.info(f"Saved protocol distribution visualization to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing protocol distribution: {str(e)}")
            return None
   
    def plot_network_graph(self, df, src_col='src_ip', dst_col='dst_ip', weight_col=None, output_file=None,
                           interactive=False, max_nodes=50):
        """
        Plot network graph of connections.
       
        Args:
            df (pandas.DataFrame): DataFrame with traffic data
            src_col (str): Column name for source IP
            dst_col (str): Column name for destination IP
            weight_col (str): Column name for edge weight (optional)
            output_file (str): Filename for output visualization
            interactive (bool): Whether to create interactive plot
            max_nodes (int): Maximum number of nodes to include in visualization
           
        Returns:
            str: Path to saved visualization file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_network_graph.{'html' if interactive else 'png'}"
           
        output_path = os.path.join(self.output_dir, output_file)
       
        try:
            # Create graph
            G = nx.DiGraph()
           
            # Create edges
            edge_weights = {}
            for _, row in df.iterrows():
                src = row[src_col]
                dst = row[dst_col]
               
                if pd.isna(src) or pd.isna(dst):
                    continue
                   
                edge = (src, dst)
                if edge in edge_weights:
                    edge_weights[edge] += 1 if weight_col is None else row[weight_col]
                else:
                    edge_weights[edge] = 1 if weight_col is None else row[weight_col]
           
            # Add edges to graph
            for (src, dst), weight in edge_weights.items():
                G.add_edge(src, dst, weight=weight)
           
            # Limit to top nodes if graph is too large
            if len(G.nodes) > max_nodes:
                # Keep nodes with highest degree
                sorted_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
                nodes_to_keep = [node for node, _ in sorted_nodes]
                G = G.subgraph(nodes_to_keep)
           
            if interactive:
                # Create interactive network visualization with Plotly
                pos = nx.spring_layout(G)
               
                # Create edge trace
                edge_x = []
                edge_y = []
                edge_text = []
               
                for edge in G.edges(data=True):
                    x0, y0 = pos[edge[0]]
                    x1, y1 = pos[edge[1]]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
                    edge_text.append(f"{edge[0]} → {edge[1]}: {edge[2]['weight']}")
               
                edge_trace = go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=0.5, color='#888'),
                    hoverinfo='text',
                    text=edge_text,
                    mode='lines')
               
                # Create node trace
                node_x = []
                node_y = []
                node_text = []
                node_size = []
               
                for node in G.nodes():
                    x, y = pos[node]
                    node_x.append(x)
                    node_y.append(y)
                    node_text.append(f"IP: {node}<br>Connections: {G.degree(node)}")
                    node_size.append(10 + 2 * G.degree(node))
               
                node_trace = go.Scatter(
                    x=node_x, y=node_y,
                    mode='markers',
                    hoverinfo='text',
                    text=node_text,
                    marker=dict(
                        showscale=True,
                        colorscale='YlGnBu',
                        color=[G.degree(node) for node in G.nodes()],
                        size=node_size,
                        colorbar=dict(
                            thickness=15,
                            title='Node Connections',
                            xanchor='left',
                            titleside='right'
                        ),
                        line_width=2))
               
                # Create figure
                fig = go.Figure(data=[edge_trace, node_trace],
                             layout=go.Layout(
                                title='Network Traffic Graph',
                                titlefont=dict(size=16),
                                showlegend=False,
                                hovermode='closest',
                                margin=dict(b=20,l=5,r=5,t=40),
                                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                                )
               
                fig.write_html(output_path)
            else:
                # Create static network visualization with Matplotlib and NetworkX
                plt.figure(figsize=(12, 10))
               
                # Use different layouts depending on graph size
                if len(G.nodes) < 20:
                    pos = nx.spring_layout(G)
                else:
                    pos = nx.kamada_kawai_layout(G)
               
                # Get edge weights for width
                edge_weights = [G[u][v]['weight'] for u, v in G.edges()]
                max_weight = max(edge_weights)
                normalized_weights = [3.0 * w / max_weight for w in edge_weights]
               
                # Draw edges with width proportional to weight
                nx.draw_networkx_edges(G, pos, width=normalized_weights, alpha=0.7,
                                      edge_color='grey', arrows=True)
               
                # Draw nodes with size proportional to degree
                node_sizes = [300 * (1 + G.degree(node) / 10) for node in G.nodes()]
                nx.draw_networkx_nodes(G, pos, node_size=node_sizes,
                                      node_color=[G.degree(node) for node in G.nodes()],
                                      cmap=plt.cm.YlGnBu)
               
                # Add labels to nodes
                nx.draw_networkx_labels(G, pos, font_size=8, font_color='black')
               
                plt.title('Network Traffic Graph')
                plt.axis('off')
                plt.tight_layout()
                plt.savefig(output_path)
                plt.close()
           
            self.logger.info(f"Saved network graph visualization to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing network graph: {str(e)}")
            return None
   
    def plot_anomaly_timeline(self, df, time_col='timestamp', is_anomaly_col='is_anomaly',
                             score_col=None, output_file=None, interactive=False):
        """
        Plot timeline of detected anomalies.
       
        Args:
            df (pandas.DataFrame): DataFrame with anomaly detection results
            time_col (str): Column name for timestamp
            is_anomaly_col (str): Column name for anomaly flag
            score_col (str): Column name for anomaly score (optional)
            output_file (str): Filename for output visualization
            interactive (bool): Whether to create interactive plot
           
        Returns:
            str: Path to saved visualization file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_anomaly_timeline.{'html' if interactive else 'png'}"
           
        output_path = os.path.join(self.output_dir, output_file)
       
        try:
            # Ensure timestamp is datetime
            if df[time_col].dtype != 'datetime64[ns]':
                df = df.copy()
                df['datetime'] = pd.to_datetime(df[time_col], unit='s')
                time_col = 'datetime'
           
            if interactive:
                # Create interactive plot with Plotly
                fig = make_subplots(rows=2, cols=1, shared_xaxes=True,
                                    subplot_titles=('Anomaly Timeline', 'Anomaly Score' if score_col else ''),
                                    vertical_spacing=0.1)
               
                # Plot anomaly flags
                fig.add_trace(
                    go.Scatter(x=df[time_col], y=df[is_anomaly_col], mode='markers',
                              marker=dict(
                                  size=10,
                                  color=df[is_anomaly_col],
                                  colorscale=[[0, 'green'], [1, 'red']],
                                  showscale=False
                              ),
                              name='Anomaly'),
                    row=1, col=1
                )
               
                # Plot anomaly score if available
                if score_col:
                    fig.add_trace(
                        go.Scatter(x=df[time_col], y=df[score_col], mode='lines',
                                  name='Anomaly Score'),
                        row=2, col=1
                    )
               
                fig.update_layout(
                    title='Anomaly Detection Timeline',
                    height=700
                )
               
                fig.write_html(output_path)
            else:
                # Create static plot with Matplotlib
                plt.figure(figsize=(15, 8))
               
                # Plot anomaly flags
                plt.subplot(2, 1, 1)
                plt.scatter(df[time_col], df[is_anomaly_col], c=df[is_anomaly_col], cmap='RdYlGn_r')
                plt.title('Anomaly Timeline')
                plt.ylabel('Is Anomaly')
               
                # Plot anomaly score if available
                if score_col:
                    plt.subplot(2, 1, 2)
                    plt.plot(df[time_col], df[score_col])
                    plt.title('Anomaly Score')
                    plt.ylabel('Score')
               
                plt.tight_layout()
                plt.savefig(output_path)
                plt.close()
           
            self.logger.info(f"Saved anomaly timeline visualization to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing anomaly timeline: {str(e)}")
            return None
