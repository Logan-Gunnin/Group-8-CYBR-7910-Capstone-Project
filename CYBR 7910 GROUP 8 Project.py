from dash import Dash, dcc, html, Input, Output
import plotly.graph_objects as go
import plotly.express as px
import os
import pandas as pd


APP_LOCATION = os.path.dirname(os.path.abspath(__file__))
LOGs_LOCATION = os.path.join(APP_LOCATION, "data")

csv_files = [
    "Dataset 3__Malware_Threat_Alerts.csv",
    "Dataset 4__Network_Traffic_Summary.csv"
]
csv_dfs = {
    file: pd.read_csv(os.path.join(LOGs_LOCATION, file))
    for file in csv_files
}

Excel_Logs = "Dataset 1__Web_Server_Access_Logs.xlsx"
excel_path = os.path.join(LOGs_LOCATION, excel_file)
excel_sheets = pd.read_excel(excel_path, sheet_name=None)

excel_dfs = {
    f"{excel_file} - {sheet}": df
    for sheet, df in excel_sheets.items()
}

all_sources = {**csv_dfs, **excel_dfs}
source_names = list(all_sources.keys())


app.layout = html.Div([
    html.H4(' This gives a color selection'),
    html.P(" Select your Color:"),
    dcc.Dropdown(
        id="dropdown",
        options=['Gold', 'MediumTurquoise', 'LightGreen'],
        value='Gold',
        clearable=False,
    ),
    dcc.Graph(id="graph-1"),
])
@app.callback(
    Output("graph-1", "figure"),
    Input("dropdown", "value"))
def display_color(color):
    fig = go.Figure(
        data=go.Bar(y=[2, 3, 1], # replace with your own data source
                    marker_color=color))
    return fig


app.run(debug=True)