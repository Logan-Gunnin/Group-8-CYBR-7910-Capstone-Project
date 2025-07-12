from dash import Dash, dcc, html, Input, Output
import pandas as pd
import os
import plotly.graph_objects as go

# Had to use fixed location since the API I tried to use didn't work
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

# LOCAL FILE PATHS MUST HAVE ALL FILES IN THE SAME FOLDER
APP_LOCATION = os.path.dirname(os.path.abspath(__file__))
LOGS_LOCATION = APP_LOCATION

csv_datasets_loaded = [
    "Dataset 3__Malware_Threat_Alerts.csv",
    "Dataset 4__Network_Traffic_Summary.csv",
    "Dateset 2__User_Authentication_Logs.csv", 
    "Dataset 5__Security_Incident_Reports.csv"
]

csv_datasets = {
    file: pd.read_csv(os.path.join(LOGS_LOCATION, file), encoding='utf-8')
    for file in csv_datasets_loaded
}

app = Dash(__name__)

app.layout = html.Div([
    html.H2('📊 Security Dashboard'),

    dcc.Tabs(id="tabs", value='tab-user-monitoring', children=[
        dcc.Tab(label='User Behavior & Access Monitoring', value='tab-user-monitoring'),
        dcc.Tab(label='Threat Detection & Malware Insights', value='tab-threat-malware'),
        dcc.Tab(label='Network and Incident Response', value='tab-network-response'),
    ]),

    html.Div(id='tabs-content')
])

@app.callback(
    Output('tabs-content', 'children'),
    Input('tabs', 'value')
)
def render_tab_content(tab):
    if tab == 'tab-user-monitoring':
        return html.Div([
            html.H3('User Behavior & Access Monitoring'),

            dcc.RadioItems(
                id='user-behavior-subfunc',
                options=[
                    {'label': 'Failed Login Heatmap', 'value': 'failed_heatmap'},
                    {'label': 'City/State/Country Login Trends', 'value': 'location_trends'},
                    {'label': 'Business Hours vs Non-business Hours', 'value': 'business_hours'},
                    {'label': 'User Agent/Browser Distribution', 'value': 'user_agent_dist'}
                ],
                value='failed_heatmap',
                inline=True
            ),

            dcc.Graph(id='user-behavior-graph')
        ])

    elif tab == 'tab-threat-malware':
        return html.Div([
            html.H3('Threat Detection & Malware Insights'),
            html.P("Content coming soon...")
        ])

    else:
        return html.Div([
            html.H3('Network and Incident Response'),
            html.P("Content coming soon...")
        ])

@app.callback(
    Output('user-behavior-graph', 'figure'),
    Input('user-behavior-subfunc', 'value')
)
def update_user_behavior_graph(subfunc):
    if subfunc == 'failed_heatmap':
        df = csv_datasets["Dateset 2__User_Authentication_Logs.csv"]

        # Filter failed and successful logins with geo_location
        denied = df[df['login_status'].str.lower() == 'failure'].dropna(subset=['geo_location'])
        approved = df[df['login_status'].str.lower() == 'success'].dropna(subset=['geo_location'])

        def map_lat_lon(location):
            return location_cache.get(location, (None, None))

        # Group counts per location
        fail_counts = denied.groupby('geo_location').size().rename('fail_count')
        success_counts = approved.groupby('geo_location').size().rename('success_count')

        # Combine counts on geo_location
        Heatmap = pd.concat([fail_counts, success_counts], axis=1).fillna(0).reset_index()

        # Map lat/lon
        Heatmap['lat'], Heatmap['lon'] = zip(*Heatmap['geo_location'].map(map_lat_lon))

        # Drop rows missing coordinates
        Heatmap = Heatmap.dropna(subset=['lat', 'lon'])

        # Marker sizes (scaled)
        max_marker_size = 40
        Heatmap['fail_size'] = Heatmap['fail_count'] / Heatmap['fail_count'].max() * max_marker_size
        Heatmap['success_size'] = Heatmap['success_count'] / Heatmap['success_count'].max() * max_marker_size

        fig = go.Figure()

        for idx, row in Heatmap.iterrows():
            success_bigger = row['success_count'] >= row['fail_count']

            if success_bigger:
                # Success circle faded behind
                fig.add_trace(go.Scattergeo(
                    lon=[row['lon']],
                    lat=[row['lat']],
                    mode='markers',
                    marker=dict(
                        size=row['success_size'],
                        color='blue',
                        opacity=0.3,
                        symbol='circle',
                        line=dict(width=1, color='white')
                    ),
                    name='Successful Logins',
                    showlegend=idx == 0,
                    hoverinfo='skip'
                ))
                if row['fail_count'] > 0:
                    # Fail circle solid front with hover info
                    fig.add_trace(go.Scattergeo(
                        lon=[row['lon']],
                        lat=[row['lat']],
                        mode='markers',
                        marker=dict(
                            size=row['fail_size'],
                            color='red',
                            opacity=0.7,
                            symbol='diamond',
                            line=dict(width=1, color='white')
                        ),
                        name='Failed Logins',
                        showlegend=idx == 0,
                        hovertemplate=(
                            f"<b>{row['geo_location']}</b><br>"
                            f"Successful Logins: {int(row['success_count'])}<br>"
                            f"Failed Logins: {int(row['fail_count'])}<extra></extra>"
                        )
                    ))
            else:
                # Fail circle faded behind
                fig.add_trace(go.Scattergeo(
                    lon=[row['lon']],
                    lat=[row['lat']],
                    mode='markers',
                    marker=dict(
                        size=row['fail_size'],
                        color='red',
                        opacity=0.3,
                        symbol='diamond',
                        line=dict(width=1, color='white')
                    ),
                    name='Failed Logins',
                    showlegend=idx == 0,
                    hoverinfo='skip'
                ))
                if row['success_count'] > 0:
                    # Success circle solid front with hover info
                    fig.add_trace(go.Scattergeo(
                        lon=[row['lon']],
                        lat=[row['lat']],
                        mode='markers',
                        marker=dict(
                            size=row['success_size'],
                            color='blue',
                            opacity=0.7,
                            symbol='circle',
                            line=dict(width=1, color='white')
                        ),
                        name='Successful Logins',
                        showlegend=idx == 0,
                        hovertemplate=(
                            f"<b>{row['geo_location']}</b><br>"
                            f"Successful Logins: {int(row['success_count'])}<br>"
                            f"Failed Logins: {int(row['fail_count'])}<extra></extra>"
                        )
                    ))

        fig.update_layout(
            title='Login Attempts by Location',
            geo=dict(
                scope='world',
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                showcountries=True,
                countrycolor='rgb(204, 204, 204)',
            ),
            legend=dict(
                title='Login Status',
                x=0.8,
                y=0.9,
                bgcolor='rgba(255,255,255,0.7)'
            )
        )

        return fig

    # Your other subfuncs here (unchanged)
    elif subfunc == 'location_trends':
        fig = go.Figure(go.Bar(
            x=['New York', 'California', 'Texas'],
            y=[100, 80, 60],
            marker_color='mediumturquoise'
        ))
        fig.update_layout(title='Login Trends by Location')
        return fig

    elif subfunc == 'business_hours':
        fig = go.Figure(go.Pie(
            labels=['Business Hours', 'Non-Business Hours'],
            values=[75, 25]
        ))
        fig.update_layout(title='Access During Business vs Non-Business Hours')
        return fig

    elif subfunc == 'user_agent_dist':
        fig = go.Figure(go.Bar(
            x=['Chrome', 'Firefox', 'Edge', 'Safari'],
            y=[120, 40, 30, 10],
            marker_color='lightgreen'
        ))
        fig.update_layout(title='User Agent / Browser Distribution')
        return fig

    else:
        return go.Figure()

if __name__ == '__main__':
    app.run(debug=True)
