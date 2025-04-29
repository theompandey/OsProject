# Colab‑Compatible Buffer Overflow Anomaly Detector with Widgets

# Install required packages
# Uncomment the next line if running fresh
# !pip install scikit-learn ipywidgets

%matplotlib inline
import numpy as np
import random
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import ipywidgets as widgets
from IPython.display import display, clear_output

# 1. Train Isolation Forest on normal patterns
model = IsolationForest(
    n_estimators=150,
    contamination=0.1,
    random_state=42
)
normal_patterns = np.array([
    [50, 5, 3, 2],  #50 MB memory, 5% CPU, 3 open files, 2 threads
    [45, 4, 2, 1],
    [55, 6, 4, 3]
])
variations = np.random.normal(50, 5, (100, 4))   #Mean = 50, Standard Deviation = 5, Shape = (100, 4) → 100 rows and 4 columns
model.fit(np.vstack([normal_patterns, variations]))
threshold = model.offset_   #internally sets an anomaly boundary

# 2. Simulation and scoring
scores = []

def simulate_sample():
    if random.random() < 0.2:
        return [
            random.randint(150, 200),
            random.randint(15, 25),
            random.randint(20, 30),
            random.uniform(3.5, 5.0)
        ]
    else:
        return list(np.random.normal(50, 5, 4))   #mean, s-d, features

# 3. Plot setup graph
fig, ax = plt.subplots(figsize=(8, 4))  #8 inches wide and 4 inches tall
plot_output = widgets.Output()
progress = widgets.IntProgress(
    value=0,
    min=0,
    max=100,
    description='Threat:',
    orientation='horizontal'
)

# 4. Update functions
def update_plot():
    with plot_output:
        clear_output(wait=True)
        ax.clear()
        ax.plot(scores, marker='o', linestyle='-', label='Anomaly Score')
        ax.axhline(threshold, linestyle='--', label='Threshold')
        ax.set_title('Anomaly Detection Scores')
        ax.set_xlabel('Sample Index')
        ax.set_ylabel('IsolationForest Score')
        ax.legend()
        ax.grid(True)
        display(fig)

def update_progress(score):
    # Map scores so that lower scores (more anomalous) yield higher progress bar
    val = int(max(0, min(100, (threshold - score) * 50)))
    progress.value = val

# 5. Button callbacks
def on_simulate_clicked(_):
    feat = simulate_sample()
    score = model.decision_function([feat])[0]
    flag = model.predict([feat])[0]
    scores.append(score)
    update_plot()
    update_progress(score)
    if flag == -1:
        display(widgets.HTML("<b style='color:red'>Anomaly detected!</b>"))

def on_check_clicked(_):
    for _ in range(20):
        feat = list(np.random.normal(50, 5, 4))
        score = model.decision_function([feat])[0]
        scores.append(score)
    update_plot()

# 6. Display widgets
simulate_btn = widgets.Button(description='Simulate Attack', button_style='danger')
simulate_btn.on_click(on_simulate_clicked)

check_btn = widgets.Button(description='System Check', button_style='success')
check_btn.on_click(on_check_clicked)

ui = widgets.HBox([simulate_btn, check_btn])

display(ui, progress, plot_output)
