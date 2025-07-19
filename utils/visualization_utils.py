import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def create_threat_distribution_chart(scan_results):
    """
    Create a pie chart showing the distribution of threat levels.
    
    Args:
        scan_results: List of scan results
        
    Returns:
        plotly.graph_objects.Figure: Pie chart figure
    """
    if not scan_results:
        return None
    
    df = pd.DataFrame(scan_results)
    
    # Categorize scans
    clean_count = len(df[(df['malicious_count'] == 0) & (df['suspicious_count'] == 0) & (df['status'] == 'completed')])
    suspicious_count = len(df[(df['suspicious_count'] > 0) & (df['malicious_count'] == 0)])
    malicious_count = len(df[df['malicious_count'] > 0])
    
    labels = ['Clean', 'Suspicious', 'Malicious']
    values = [clean_count, suspicious_count, malicious_count]
    colors = ['#00ff00', '#ffaa00', '#ff0000']
    
    fig = px.pie(
        values=values,
        names=labels,
        title="Threat Distribution",
        color_discrete_sequence=colors
    )
    
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )
    
    fig.update_layout(
        showlegend=True,
        height=400,
        font=dict(size=12)
    )
    
    return fig

def create_timeline_chart(scan_results):
    """
    Create a timeline chart showing scan activity over time.
    
    Args:
        scan_results: List of scan results
        
    Returns:
        plotly.graph_objects.Figure: Timeline chart figure
    """
    if not scan_results:
        return None
    
    df = pd.DataFrame(scan_results)
    df['created_at'] = pd.to_datetime(df['created_at'])
    df['date'] = df['created_at'].dt.date
    
    # Group by date and scan type
    daily_stats = df.groupby(['date', 'scan_type']).size().reset_index(name='count')
    
    fig = px.bar(
        daily_stats,
        x='date',
        y='count',
        color='scan_type',
        title="Scan Activity Timeline",
        labels={'count': 'Number of Scans', 'date': 'Date', 'scan_type': 'Scan Type'},
        color_discrete_map={'file': '#3498db', 'url': '#e74c3c'}
    )
    
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Number of Scans",
        height=400,
        showlegend=True
    )
    
    return fig

def create_threat_heatmap(scan_results):
    """
    Create a heatmap showing threat activity by day and hour.
    
    Args:
        scan_results: List of scan results
        
    Returns:
        plotly.graph_objects.Figure: Heatmap figure
    """
    if not scan_results:
        return None
    
    df = pd.DataFrame(scan_results)
    df['created_at'] = pd.to_datetime(df['created_at'])
    df['day_of_week'] = df['created_at'].dt.day_name()
    df['hour'] = df['created_at'].dt.hour
    df['has_threat'] = (df['malicious_count'] > 0) | (df['suspicious_count'] > 0)
    
    # Create pivot table for heatmap
    heatmap_data = df.groupby(['day_of_week', 'hour'])['has_threat'].sum().reset_index()
    heatmap_pivot = heatmap_data.pivot(index='day_of_week', columns='hour', values='has_threat').fillna(0)
    
    # Reorder days
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_pivot = heatmap_pivot.reindex(day_order)
    
    fig = px.imshow(
        heatmap_pivot,
        title="Threat Activity Heatmap (by Day and Hour)",
        labels=dict(x="Hour of Day", y="Day of Week", color="Threats Detected"),
        color_continuous_scale="Reds"
    )
    
    fig.update_layout(height=400)
    
    return fig

def create_engine_comparison_chart(analysis_results):
    """
    Create a bar chart comparing detection rates across different antivirus engines.
    
    Args:
        analysis_results: VirusTotal analysis results
        
    Returns:
        plotly.graph_objects.Figure: Bar chart figure
    """
    if not analysis_results or 'results' not in analysis_results.get('data', {}).get('attributes', {}):
        return None
    
    results = analysis_results['data']['attributes']['results']
    
    # Count detections by category
    categories = {}
    for engine, result in results.items():
        category = result.get('category', 'undetected')
        if category not in categories:
            categories[category] = 0
        categories[category] += 1
    
    # Create bar chart
    fig = px.bar(
        x=list(categories.keys()),
        y=list(categories.values()),
        title="Detection Results by Category",
        labels={'x': 'Detection Category', 'y': 'Number of Engines'},
        color=list(categories.keys()),
        color_discrete_map={
            'malicious': '#ff0000',
            'suspicious': '#ffaa00',
            'undetected': '#00ff00',
            'harmless': '#00aa00'
        }
    )
    
    fig.update_layout(
        showlegend=False,
        height=400
    )
    
    return fig

def create_risk_gauge(risk_score, max_score=10):
    """
    Create a gauge chart showing risk score.
    
    Args:
        risk_score: Current risk score
        max_score: Maximum possible score
        
    Returns:
        plotly.graph_objects.Figure: Gauge chart figure
    """
    # Determine color based on risk score
    if risk_score >= max_score * 0.7:
        color = "red"
    elif risk_score >= max_score * 0.4:
        color = "orange"
    else:
        color = "green"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = risk_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Risk Score"},
        delta = {'reference': max_score * 0.3},
        gauge = {
            'axis': {'range': [None, max_score]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, max_score * 0.3], 'color': "lightgray"},
                {'range': [max_score * 0.3, max_score * 0.7], 'color': "gray"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': max_score * 0.9
            }
        }
    ))
    
    fig.update_layout(height=300)
    
    return fig

def create_detection_trend_chart(scan_history):
    """
    Create a line chart showing detection trends over time.
    
    Args:
        scan_history: Historical scan data
        
    Returns:
        plotly.graph_objects.Figure: Line chart figure
    """
    if not scan_history:
        return None
    
    df = pd.DataFrame(scan_history)
    df['created_at'] = pd.to_datetime(df['created_at'])
    df['date'] = df['created_at'].dt.date
    
    # Calculate daily threat rates
    daily_stats = df.groupby('date').agg({
        'malicious_count': lambda x: (x > 0).sum(),
        'id': 'count'
    }).reset_index()
    
    daily_stats['threat_rate'] = daily_stats['malicious_count'] / daily_stats['id'] * 100
    
    fig = px.line(
        daily_stats,
        x='date',
        y='threat_rate',
        title="Threat Detection Rate Over Time",
        labels={'threat_rate': 'Threat Rate (%)', 'date': 'Date'},
        markers=True
    )
    
    fig.add_hline(
        y=daily_stats['threat_rate'].mean(),
        line_dash="dash",
        line_color="red",
        annotation_text="Average"
    )
    
    fig.update_layout(
        height=400,
        yaxis_title="Threat Rate (%)",
        xaxis_title="Date"
    )
    
    return fig

def create_scan_type_comparison(scan_results):
    """
    Create a comparison chart between file and URL scan results.
    
    Args:
        scan_results: List of scan results
        
    Returns:
        plotly.graph_objects.Figure: Comparison chart figure
    """
    if not scan_results:
        return None
    
    df = pd.DataFrame(scan_results)
    
    # Separate file and URL scans
    file_scans = df[df['scan_type'] == 'file']
    url_scans = df[df['scan_type'] == 'url']
    
    # Calculate statistics
    stats = []
    
    for scan_type, data in [('File Scans', file_scans), ('URL Scans', url_scans)]:
        if len(data) > 0:
            total = len(data)
            malicious = len(data[data['malicious_count'] > 0])
            suspicious = len(data[data['suspicious_count'] > 0])
            clean = total - malicious - suspicious
            
            stats.extend([
                {'Type': scan_type, 'Category': 'Malicious', 'Count': malicious, 'Percentage': malicious/total*100},
                {'Type': scan_type, 'Category': 'Suspicious', 'Count': suspicious, 'Percentage': suspicious/total*100},
                {'Type': scan_type, 'Category': 'Clean', 'Count': clean, 'Percentage': clean/total*100}
            ])
    
    if not stats:
        return None
    
    stats_df = pd.DataFrame(stats)
    
    fig = px.bar(
        stats_df,
        x='Type',
        y='Percentage',
        color='Category',
        title="Scan Results Comparison: Files vs URLs",
        labels={'Percentage': 'Percentage (%)', 'Type': 'Scan Type'},
        color_discrete_map={
            'Malicious': '#ff0000',
            'Suspicious': '#ffaa00',
            'Clean': '#00ff00'
        }
    )
    
    fig.update_layout(
        height=400,
        yaxis_title="Percentage (%)",
        barmode='stack'
    )
    
    return fig

def create_summary_metrics_chart(scan_results):
    """
    Create a summary metrics chart with key performance indicators.
    
    Args:
        scan_results: List of scan results
        
    Returns:
        plotly.graph_objects.Figure: Metrics chart figure
    """
    if not scan_results:
        return None
    
    df = pd.DataFrame(scan_results)
    
    # Calculate metrics
    total_scans = len(df)
    completed_scans = len(df[df['status'] == 'completed'])
    total_threats = len(df[df['malicious_count'] > 0])
    avg_detection_rate = df['malicious_count'].mean() if len(df) > 0 else 0
    
    metrics = [
        {'Metric': 'Total Scans', 'Value': total_scans},
        {'Metric': 'Completed Scans', 'Value': completed_scans},
        {'Metric': 'Threats Detected', 'Value': total_threats},
        {'Metric': 'Avg Detection Rate', 'Value': round(avg_detection_rate, 2)}
    ]
    
    metrics_df = pd.DataFrame(metrics)
    
    fig = px.bar(
        metrics_df,
        x='Metric',
        y='Value',
        title="Security Metrics Summary",
        color='Value',
        color_continuous_scale='viridis'
    )
    
    fig.update_layout(
        height=400,
        showlegend=False
    )
    
    return fig

