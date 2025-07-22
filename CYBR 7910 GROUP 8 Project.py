from dash import Dash, dcc, html, Input, Output
import pandas as pd
import os
import plotly.graph_objects as go

import pytz

import plotly.express as px

location_cache = {
    "Toronto, Canada": (43.65107, -79.347015),
    "Cape Town, South Africa": (-33.9249, 18.4241),
    "San Francisco, USA": (37.7749, -122.4194),
    "New York, USA": (40.7128, -74.0060),
    "São Paulo, Brazil": (-23.5505, -46.6333),
    "Sydney, Australia": (-33.8688, 151.2093),
    "Tokyo, Japan": (35.6762, 139.6503),
    "Berlin, Germany": (52.52, 13.4050),
    "Mumbai, India": (19.0760, 72.8777),
    "London, UK": (51.5074, -0.1278)
}

APP_LOCATION = os.path.dirname(os.path.abspath(__file__))
LOGS_LOCATION = APP_LOCATION

csv_datasets_loaded = [
    "Dataset 3__Malware_Threat_Alerts.csv",
    "Dataset 4__Network_Traffic_Summary.csv",
    "Dateset 2__User_Authentication_Logs.csv",

    "Dataset 5__Security_Incident_Reports.csv"
]

tab_style = {
    'backgroundColor': '#252525',
    'color': 'white',
    'border': 'none',
    'padding': '10px',
    'fontWeight': 'normal',
}

selected_tab_style = {
    'backgroundColor': '#444444',
    'color': 'white',
    'border': 'none',
    'padding': '10px',
    'fontWeight': 'bold',
}

tabs_info = [
    {'label': 'User Behavior & Access Monitoring', 'value': 'User Login Data'},
    {'label': 'Threat Detection & Malware Insights', 'value': 'Malware and Threat Data'},
    {'label': 'Network and Incident Response', 'value': 'Network and Response Data'},
]

tabs = dcc.Tabs(
    id='app functions',
    value='User Login Data',
    children=[
        dcc.Tab(
            label=tab['label'],
            value=tab['value'],
            style=tab_style,
            selected_style=selected_tab_style,
        ) for tab in tabs_info
    ],
    style={
        'backgroundColor': '#252525',
        'borderBottom': '1px solid #444',
        'color': 'white',
    }
)
city_times = {
    city: tz for city, tz in {
        "Toronto, Canada": 'America/Toronto',
        "Cape Town, South Africa": 'Africa/Johannesburg',
        "San Francisco, USA": 'America/Los_Angeles',
        "New York, USA": 'America/New_York',
        "São Paulo, Brazil": 'America/Sao_Paulo',
        "Sydney, Australia": 'Australia/Sydney',
        "Tokyo, Japan": 'Asia/Tokyo',
        "Berlin, Germany": 'Europe/Berlin',
        "Mumbai, India": 'Asia/Kolkata',
        "London, UK": 'Europe/London'
    }.items()
}
csv_datasets = {}
for file in csv_datasets_loaded:
    try:
        df = pd.read_csv(os.path.join(LOGS_LOCATION, file), encoding='utf-8')
        csv_datasets[file] = df

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file}")

    except pd.errors.ParserError as e:
        print(f"[ERROR] Parsing CSV failed for {file}: {e}")

app = Dash(__name__, suppress_callback_exceptions=True)

app.layout = html.Div([

    html.H2('Data Science Dashboard for EverythingOrganic', style={
        'color': 'white',
        'backgroundColor': '#252525',
        'margin': '0',
        'padding': '0',
    }),

    tabs,

    html.Div(id='tab display', style={'color': 'white', 'padding': '45px'})
],
    style={
        'backgroundColor': "#252525",
        'minHeight': '100vh',
        'margin': '0',
        'padding': '0',
        'fontFamily': 'Arial, sans-serif'
    })


@app.callback(
    Output('tab display', 'children'),
    Input('app functions', 'value')
)
def render_tab_content(tab):
    if tab == 'User Login Data':
        return html.Div([
            html.H3('User Behavior & Access Monitoring'),

            dcc.Tabs(
                id='user-subtab',
                value='heatmap',
                children=[
                    dcc.Tab(label='Failed Login Heatmap', value='heatmap'),
                    dcc.Tab(label='Business Hours vs Non-Business Hours', value='business_hours'),
                    dcc.Tab(label='Browser Distribution', value='user_agent')
                ],
                style={'backgroundColor': '#252525', 'color': 'grey'}  # This style now correctly applies to the Tabs
            ),

            html.Div(id='user-subtab-content')
        ])

    elif tab == 'Malware and Threat Data':
        return html.Div([
            html.H3('Threat Detection & Malware Insights'),

            dcc.Tabs(id='Malware Sub Function', value='threats', children=[
                dcc.Tab(label='Threat Types', value='threats'),
                dcc.Tab(label='Remediation Status', value='remediation')
            ], style={'backgroundColor': '#252525', 'color': 'grey'}),

            html.Div(id='Malware Content')

        ])

    elif tab == 'Network and Response Data':
        return html.Div([
            html.H3('Network and Incident Response'),

            dcc.Tabs(id='network-subtab', value='protocol_traffic', children=[
                dcc.Tab(label='Protocol Traffic vs Suspicious Activity', value='protocol_traffic'),
                dcc.Tab(label='Inbound/Outbound Byte Averages', value='byte_avg'),
                dcc.Tab(label='Total vs Suspicious Byte Volume', value='byte_comparison'),
                dcc.Tab(label='Top Incident Categories', value='category'),
                dcc.Tab(label='Incident Response Time Analysis', value='response_time')
            ], style={'backgroundColor': '#252525', 'color': 'grey'}),

            html.Div(id='network-subtab-content')
        ])


@app.callback(
    Output('user-subtab-content', 'children'),
    Input('user-subtab', 'value')
)
def update_user_behavior_graph(user_login_location):
    if user_login_location == 'heatmap':
        # heatmap success and fail
        df = csv_datasets["Dateset 2__User_Authentication_Logs.csv"]
        denied = df[df['login_status'].str.lower() == 'failure'].dropna(subset=['geo_location'])
        approved = df[df['login_status'].str.lower() == 'success'].dropna(subset=['geo_location'])

        def map_lat_lon(location):
            return location_cache.get(location, (None, None))

        fail_counts = denied.groupby('geo_location').size().rename('fail_count')
        success_counts = approved.groupby('geo_location').size().rename('success_count')
        Heatmap = pd.concat([fail_counts, success_counts], axis=1).fillna(0).reset_index()
        Heatmap['lat'], Heatmap['lon'] = zip(*Heatmap['geo_location'].map(map_lat_lon))
        Heatmap = Heatmap.dropna(subset=['lat', 'lon'])

        max_marker_size = 40
        Heatmap['fail_size'] = Heatmap['fail_count'] / Heatmap['fail_count'].max() * max_marker_size
        Heatmap['success_size'] = Heatmap['success_count'] / Heatmap['success_count'].max() * max_marker_size

        fig = go.Figure()
        for idx, row in Heatmap.iterrows():
            if row['fail_count'] <= row['success_count']:
                fig.add_trace(go.Scattergeo(
                    lon=[row['lon']], lat=[row['lat']], mode='markers',
                    marker=dict(size=row['fail_size'], color='red', opacity=0.3, symbol='diamond',
                                line=dict(width=1, color='white')),
                    name='Failed Logins', showlegend=idx == 0, hoverinfo='skip'
                ))
                if row['success_count'] > 0:
                    fig.add_trace(go.Scattergeo(
                        lon=[row['lon']], lat=[row['lat']], mode='markers',
                        marker=dict(size=row['success_size'], color='blue', opacity=0.7, symbol='circle',
                                    line=dict(width=1, color='white')),
                        name='Successful Logins', showlegend=idx == 0,
                        hovertemplate=(
                            f"<b>{row['geo_location']}</b><br>Successful Logins: {int(row['success_count'])}<br>Failed Logins: {int(row['fail_count'])}<extra></extra>")
                    ))
            else:
                fig.add_trace(go.Scattergeo(
                    lon=[row['lon']], lat=[row['lat']], mode='markers',
                    marker=dict(size=row['success_size'], color='blue', opacity=0.3, symbol='circle',
                                line=dict(width=1, color='white')),
                    name='Successful Logins', showlegend=idx == 0, hoverinfo='skip'
                ))
                if row['fail_count'] > 0:
                    fig.add_trace(go.Scattergeo(
                        lon=[row['lon']], lat=[row['lat']], mode='markers',
                        marker=dict(size=row['fail_size'], color='red', opacity=0.7, symbol='diamond',
                                    line=dict(width=1, color='white')),
                        name='Failed Logins', showlegend=idx == 0,
                        hovertemplate=(
                            f"<b>{row['geo_location']}</b><br>Successful Logins: {int(row['success_count'])}<br>Failed Logins: {int(row['fail_count'])}<extra></extra>")
                    ))

        fig.update_layout(
            title='Login Attempts by Location',
            geo=dict(scope='world', projection_type='natural earth', showland=True, landcolor='rgb(243, 243, 243)',
                     showcountries=True, countrycolor='rgb(204, 204, 204)'),
            paper_bgcolor='#252525',
            plot_bgcolor='#252525',
            font_color='white'
        )
        return dcc.Graph(figure=fig)

    elif user_login_location == 'business_hours':
        df = csv_datasets["Dateset 2__User_Authentication_Logs.csv"].copy()
        df['timestamp'] = pd.to_datetime(df['login_timestamp'], utc=True)

        def convert_to_local_time(row):
            tz_name = city_times.get(row['geo_location'])
            if not tz_name:
                return None
            local_tz = pytz.timezone(tz_name)
            return row['timestamp'].astimezone(local_tz)

        df['local_time'] = df.apply(convert_to_local_time, axis=1)

        def classify_business_hours(local_time):
            if pd.isnull(local_time):
                return 'Unknown'
            hour = local_time.hour
            return 'Business Hours' if 9 <= hour < 17 else 'Non-Business Hours'

        df['business_hours'] = df['local_time'].apply(classify_business_hours)
        grouped = df.groupby(['geo_location', 'business_hours']).size().reset_index(name='count')

        fig = px.bar(
            grouped,
            x='geo_location',
            y='count',
            color='business_hours',
            barmode='group',
            title='Logins During Business vs Non-Business Hours by Location'
        )

        fig.update_layout(
            xaxis_title='City, Country',
            yaxis_title='Number of Logins',
            paper_bgcolor='#252525',
            plot_bgcolor='#252525',
            font_color='white',
            legend_title='Time Category'
        )
        return dcc.Graph(figure=fig)

    elif user_login_location == 'user_agent':
        df = csv_datasets["Dateset 2__User_Authentication_Logs.csv"].copy()
        browser_counts = df['user_agent'].value_counts().reset_index()
        browser_counts.columns = ['Browser', 'Count']

        fig = px.pie(
            browser_counts,
            names='Browser',
            values='Count',
            title='User Agent / Browser Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )

        fig.update_layout(
            paper_bgcolor='#252525',
            plot_bgcolor='#252525',
            font_color='white',
        )

        return dcc.Graph(figure=fig)

    else:
        return html.P("Invalid subtab selection.")


@app.callback(
    Output('Malware Content', 'children'),
    Input('Malware Sub Function', 'value')
)
def render_malware_subtab(subtab):
    df = csv_datasets["Dataset 3__Malware_Threat_Alerts.csv"]

    if subtab == 'threats':
        malware_counts = df['threat_type'].value_counts().reset_index()
        malware_counts.columns = ['Malware Type', 'Count']

        fig = px.pie(
            malware_counts,
            names='Malware Type',
            values='Count',
            title='Malware Distribution by Type',
            color_discrete_sequence=px.colors.qualitative.Bold
        )

        fig.update_layout(
            paper_bgcolor='#252525',
            plot_bgcolor='#252525',
            font_color='white',
            legend_title_text='Type'
        )

        return dcc.Graph(figure=fig)

    elif subtab == 'remediation':
        status_counts = df['remediation_status'].value_counts().reset_index()
        status_counts.columns = ['Remediation Status', 'Count']

        pending = df[df['remediation_status'] == 'Pending']
        pending_counts = pending.threat_type.value_counts().nlargest(5).reset_index()
        pending_counts.columns = ['Threat Type', 'Count']

        escalated = df[df['remediation_status'] == 'Escalated']
        escalated_counts = escalated.threat_type.value_counts().nlargest(5).reset_index()
        escalated_counts.columns = ['Threat Type', 'Count']

        pie_fig = px.pie(
            status_counts,
            names='Remediation Status',
            values='Count',
            title='Malware Remediation Status Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )

        pending_bar_fig = px.bar(
            pending_counts,
            x='Threat Type',
            y='Count',
            title='Top 5 Pending Threat Types',
            color='Threat Type'
        )

        escalated_bar_fig = px.bar(
            escalated_counts,
            x='Threat Type',
            y='Count',
            title='Top 5 Escalated Threat Types',
            color='Threat Type'
        )

        return html.Div([
            dcc.Graph(figure=pie_fig),
            html.Br(),
            dcc.Graph(figure=pending_bar_fig),
            html.Br(),
            dcc.Graph(figure=escalated_bar_fig)
        ])

    else:
        return html.P("No data available for this subtab.")


@app.callback(
    Output('network-subtab-content', 'children'),
    Input('network-subtab', 'value')
)
def render_network_subtab(subtab): 
    try:
        df_traffic = csv_datasets["Dataset 4__Network_Traffic_Summary.csv"].copy()
        df_incident = csv_datasets["Dataset 5__Security_Incident_Reports.csv"].copy()
    except KeyError as e:
        return html.P(f"Missing dataset: {e}", style={"color": "red"})

    def _layout(fig, title):
        fig.update_layout(
            title=title,
            paper_bgcolor="#252525",
            plot_bgcolor="#252525",
            font_color="white",
            legend_title=None,
            margin=dict(t=60, l=40, r=20, b=40)
        )
        return dcc.Graph(figure=fig)

    if subtab == "protocol_traffic":
        if df_traffic.empty:
            return html.P("No traffic data available.", style={"color": "white"})
        g = df_traffic.groupby(["protocol", "suspicious_activity"]).size().reset_index(name="Events")
        fig = px.bar(g, x="protocol", y="Events", color="suspicious_activity", barmode="group")
        return _layout(fig, "Protocol Traffic vs Suspicious Activity")

    elif subtab == "byte_avg":
        if df_traffic.empty:
            return html.P("No traffic data available.", style={"color": "white"})
        g = (
            df_traffic
            .groupby("suspicious_activity")[["inbound_bytes", "outbound_bytes"]]
            .mean()
            .reset_index()
            .melt(id_vars="suspicious_activity", var_name="Direction", value_name="Average Bytes")
        )
        fig = px.bar(g, x="suspicious_activity", y="Average Bytes", color="Direction", barmode="group")
        return _layout(fig, "Average Inbound / Outbound Bytes")

    elif subtab == "byte_comparison":
        if df_traffic.empty:
            return html.P("No traffic data available.", style={"color": "white"})
        df_traffic["total_bytes"] = df_traffic["inbound_bytes"] + df_traffic["outbound_bytes"]
        g = (
            df_traffic
            .groupby("protocol")[["inbound_bytes", "outbound_bytes", "total_bytes"]]
            .sum()
            .reset_index()
            .melt(id_vars="protocol", var_name="Byte Type", value_name="Bytes")
        )
        fig = px.bar(g, x="protocol", y="Bytes", color="Byte Type", barmode="group")
        return _layout(fig, "Inbound vs Outbound vs Total Bytes by Protocol")

    elif subtab == "category":
        if df_incident.empty:
            return html.P("No incident data available.", style={"color": "white"})
        g = df_incident.groupby("category").size().reset_index(name="Count")
        g = g.sort_values("Count", ascending=False).head(10)
        fig = px.pie(
            g,
            names="category",
            values="Count",
            title="Top 10 Incident Categories",
            hole=0.3
        )
        fig.update_traces(textinfo='percent+label')
        return _layout(fig, "Top Incident Categories")

    elif subtab == "response_time":
        if df_incident.empty:
            return html.P("No incident data available.", style={"color": "white"})
        df_incident = df_incident.dropna(subset=["response_time_minutes"])
        df_incident["response_hrs"] = df_incident["response_time_minutes"] / 60

        if df_incident.empty:
            return html.P("No valid response time data found.", style={"color": "white"})

        avg_rt = df_incident["response_hrs"].mean()
        fig = px.histogram(df_incident, x="response_hrs", nbins=30, labels={"response_hrs": "Hours"})
        fig.add_vline(
            x=avg_rt,
            line_dash="dash",
            annotation_text=f"Mean = {avg_rt:.1f} h",
            annotation_position="top right"
        )
        return _layout(fig, "Incident Response Time Distribution")

    return html.P("No data available for this sub-tab.", style={"color": "white"})

if __name__ == '__main__':
    app.run(debug=True)
