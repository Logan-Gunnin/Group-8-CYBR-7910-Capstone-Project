from dash import Dash, dcc, html, Input, Output
import pandas as pd
import os
import plotly.graph_objects as go

import pytz

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

            dcc.Dropdown(
                id='User behavior and access',
                options=[
                    {'label': 'Failed Login Heatmap', 'value': 'heatmap success and fail'},
                    {'label': 'City and Country Login Trends', 'value': 'location_trends'},
                    {'label': 'Business Hours vs Non-business Hours', 'value': 'business_hours'},
                    {'label': 'Browser Distribution', 'value': 'user_agent_dist'}
    ],
    value='heatmap success and fail',
    clearable=False,
    searchable=False,
    style={'width': '300px', 'color': 'white', 'backgroundColor' : '#FFFFF', 'padding': '5px', 'fontWeight': 'bold', 'width': '400px', 'zIndex': 9999, 'position': 'relative'
},
    
),

            dcc.Graph(id='graph of user behavior and access monitoring')
        ])

    elif tab == 'Malware and Threat Data':
        return html.Div([
            html.H3('Threat Detection & Malware Insights'),
            html.P("Cneed to finish this one")
        ])

    else:
        return html.Div([
            html.H3('Network and Incident Response'),
            html.P("this is for the last section need to be done next week")
        ])

@app.callback(
    Output('graph of user behavior and access monitoring', 'figure'),
    Input('User behavior and access', 'value')
)
def update_user_behavior_graph(user_login_location):
    if user_login_location == 'heatmap success and fail':
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
            success_bigger = row['success_count'] >= row['fail_count']

            if row['fail_count'] <= row['success_count']:
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
            else:
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

        fig.update_layout(
            title={
                'text': 'Login Attempts by Location',
                'font': {'color': "#ffffff", 'size': 30}
            },
            geo=dict(
                scope='world',
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                showcountries=True,
                countrycolor='rgb(204, 204, 204)',
            ),
            paper_bgcolor='#252525',
            plot_bgcolor='#252525',
            legend=dict(
                title='Login Status',
                x=0.8,
                y=0.9,
                bgcolor='rgba(255,255,255,0.7)'
            )
        )
        return fig

    elif user_login_location == 'location_trends':
        fig = go.Figure(go.Bar(
            x=['New York', 'California', 'Texas'],
            y=[100, 80, 60],
            marker_color='mediumturquoise'
        ))
        fig.update_layout(title='Login Trends by Location')
        return fig

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

        import plotly.express as px
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
            plot_bgcolor='#252525',
            paper_bgcolor='#252525',
            font_color='white'
        )
        return fig

    elif user_login_location == 'user_agent_dist':
        fig = go.Figure(go.Bar(
            x=['Chrome', 'Firefox', 'Edge', 'Safari'],
            y=[58, 92, 14, 24],
            marker_color='lightgreen'
        ))
        fig.update_layout(title='User Agent / Browser Distribution')
        return fig

    else:
        return go.Figure()

if __name__ == '__main__':
    app.run(debug=True)
