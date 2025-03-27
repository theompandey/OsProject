import tkinter as tk
from tkinter import ttk, messagebox
import random
import threading
import queue
import numpy as np
from sklearn.ensemble import IsolationForest
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Set modern matplotlib style (updated for newer versions)
try:
    plt.style.use('seaborn-v0_8')  # Newer matplotlib versions
except:
    plt.style.use('ggplot')  # Fallback style


# CUSTOM MODULES
class SecurityCore:
    def _init_(self):
        self.model = self._init_model()
        self._train_model()

    def _init_model(self):
        return IsolationForest(
            n_estimators=150,
            contamination=0.1,
            random_state=42
        )

    def _train_model(self):
        normal_patterns = np.array([
            [50, 5, 3, 2],
            [45, 4, 2, 1],
            [55, 6, 4, 3]
        ])
        self.model.fit(np.vstack([
            normal_patterns,
            np.random.normal(50, 5, (100, 4))
        ]))

    def analyze_activity(self, features):
        return (
            self.model.decision_function([features])[0],
            self.model.predict([features])[0]
        )


class ThreatSimulator:
    @staticmethod
    def generate_attack():
        return {
            'length': random.randint(150, 200),
            'specials': random.randint(15, 25),
            'numbers': random.randint(20, 30),
            'entropy': random.uniform(3.5, 5.0)
        }


##inhanced interface
class SecurityDashboard:
    def _init_(self, master):
        self.master = master
        self.master.title("Security Monitor v2.1")
        self.core = SecurityCore()
        self.simulator = ThreatSimulator()

        ## Configure styles
        self._setup_styles()
        self._create_widgets()
        self._start_monitoring()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Custom styles
        style.configure('Main.TFrame', background='#f5f5f5')
        style.configure('Alert.TFrame', background='#ffebee')
        style.configure('Header.TLabel',
                        font=('Helvetica', 12, 'bold'),
                        foreground='#333333')
        style.configure('Green.TButton',
                        foreground='white',
                        background='#4CAF50',
                        font=('Helvetica', 10))

    def _create_widgets(self):
        # Main container
        self.main_frame = ttk.Frame(self.master, style='Main.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control panel
        self._create_control_panel()

        # Visualization area
        self._create_visualization()

        # Activity log
        self._create_activity_log()

    def _create_control_panel(self):
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(
            control_frame,
            text="Simulate Attack",
            style='Green.TButton',
            command=self._simulate_attack
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="System Check",
            command=self._run_system_check
        ).pack(side=tk.LEFT, padx=5)

    def _create_visualization(self):
        viz_frame = ttk.Frame(self.main_frame)
        viz_frame.pack(fill=tk.BOTH, expand=True)

        # Risk chart
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=viz_frame)
        self.canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Threat meter
        self.meter_frame = ttk.Frame(viz_frame)
        self.meter_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        ttk.Label(self.meter_frame, text="Threat Level", style='Header.TLabel').pack()
        self.threat_meter = ttk.Progressbar(
            self.meter_frame,
            orient=tk.VERTICAL,
            length=200,
            mode='determinate'
        )
        self.threat_meter.pack(pady=5)

    def _create_activity_log(self):
        log_frame = ttk.Frame(self.main_frame, style='Alert.TFrame')
        log_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(log_frame, text="Security Events", style='Header.TLabel').pack()

        self.log_text = tk.Text(
            log_frame,
            height=10,
            wrap=tk.WORD,
            bg='white',
            font=('Consolas', 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

    def _start_monitoring(self):
        self.running = True
        self.log_queue = queue.Queue()
        self.metrics = {'threats': 0, 'blocked': 0, 'checks': 0}

        self.monitor_thread = threading.Thread(target=self._monitor_activity)
        self.monitor_thread.start()
        self._update_ui()

    def _monitor_activity(self):
        while self.running:
            # Random security checks
            if random.random() < 0.3:
                features = [
                    random.randint(40, 60),
                    random.randint(3, 8),
                    random.randint(2, 6),
                    random.uniform(2.0, 4.0)
                ]
                self._check_threat(features)
            threading.Event().wait(1)

    def _check_threat(self, features):
        score, prediction = self.core.analyze_activity(features)
        if prediction == -1:
            self.metrics['threats'] += 1
            self.log_queue.put(f"[ALERT] Suspicious activity detected (score: {score:.2f})")
            self._block_threat()

    def _block_threat(self):
        self.metrics['blocked'] += 1
        self.log_queue.put("[ACTION] Threat contained")
        self.threat_meter['value'] = min(self.threat_meter['value'] + 10, 100)

    def _simulate_attack(self):
        attack = self.simulator.generate_attack()
        self.log_queue.put(f"[SIMULATION] Attack pattern: {attack}")
        features = list(attack.values())
        self.core.analyze_activity(features)

    def _run_system_check(self):
        self.log_queue.put("[SYSTEM] Running security diagnostics...")
        self.threat_meter['value'] = max(self.threat_meter['value'] - 15, 0)

    def _update_ui(self):
        # Process log entries
        while not self.log_queue.empty():
            entry = self.log_queue.get()
            self.log_text.insert(tk.END, entry + "\n")
            self.log_text.see(tk.END)

        # Update visualization
        self._update_chart()

        # Continue updates if running
        if self.running:
            self.master.after(1000, self._update_ui)

    def _update_chart(self):
        self.ax.clear()

        labels = ['Normal', 'Suspicious', 'Critical']
        sizes = [
            100 - self.metrics['threats'],
            self.metrics['threats'] - self.metrics['blocked'],
            self.metrics['blocked']
        ]

        self.ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            colors=['#4CAF50', '#FFC107', '#F44336'],
            startangle=90
        )
        self.ax.set_title('Activity Distribution')
        self.canvas.draw()

    def _shutdown(self):
        self.running = False
        self.master.destroy()


if _name_ == "_main_":
    root = tk.Tk()
    app = SecurityDashboard(root)
    root.protocol("WM_DELETE_WINDOW", app._shutdown)
    root.geometry("900x650")
    root.mainloop()




