from pyecharts.charts import Line
from pyecharts import options as opts
from pyecharts.options import GraphicGroup, GraphicRect, GraphicText
from pyecharts.render import make_snapshot
from snapshot_selenium import snapshot
import os
from config import *

methods = ['5', '10', '15', '20', '25', '30']
metrics = ['Acc.', 'Precis.', 'Recall', 'F1']

values_by_method = {
    '5': [0.90, 0.90, 0.58, 0.71],
    '10': [0.90, 0.73, 0.74, 0.73],
    '15': [0.87, 0.70, 0.74, 0.72],
    '20': [0.91, 0.79, 0.76, 0.77],
    '25': [0.89, 0.74, 0.69, 0.71],
    '30': [0.89, 0.73, 0.71, 0.72],
}

line = Line(init_opts=opts.InitOpts(width="800px", height="500px"))
line.add_xaxis(metrics)

for method, values in values_by_method.items():
    show_label = True if method == '20' else False
    line.add_yaxis(
        series_name=method,
        y_axis=values,
        is_smooth=True,
        label_opts=opts.LabelOpts(is_show=show_label)
    )

line.set_global_opts(
    # title_opts=opts.TitleOpts(title="Ablation Study (Top-N) Performance"),
    tooltip_opts=opts.TooltipOpts(trigger="axis"),
    legend_opts=opts.LegendOpts(
        pos_top="15%",     
        pos_right="10%",    
        orient="vertical", 
        item_width=20,
        item_height=14
    ),
    yaxis_opts=opts.AxisOpts(min_=0.5, max_=1.0, name="Score"),
    xaxis_opts=opts.AxisOpts(name="Metric")
)

path = os.path.join(RESULT_SAVE_PATH, "ablation_topn_line_chart.html")
line.render(path)
# make_snapshot(snapshot, line.render(), "ablation_topn_line_chart.png")