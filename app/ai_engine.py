import numpy as np
from sklearn.ensemble import IsolationForest

class AIThreatModel:
    """
    IsolationForest anomaly detection + cold-start heuristic.
    Produces (label, risk_score).
    """
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=42
        )
        self.is_trained = False

    def _vectorize(self, login_hour, file_access_count, payload_size):
        lh = 12 if login_hour is None else int(login_hour)
        fac = 0 if file_access_count is None else int(file_access_count)
        ps = 0 if payload_size is None else int(payload_size)
        # scale so payload doesn't dominate
        return np.array([[lh / 23.0, fac / 500.0, ps / 1_000_000.0]], dtype=float)

    def train(self, samples):
        """
        samples: list[(login_hour, file_access_count, payload_size)]
        """
        if len(samples) < 25:
            self.is_trained = False
            return
        X = np.vstack([self._vectorize(*s) for s in samples])
        self.model.fit(X)
        self.is_trained = True

    def score(self, login_hour, file_access_count, payload_size):
        x = self._vectorize(login_hour, file_access_count, payload_size)

        if not self.is_trained:
            # Cold start: conservative heuristic risk
            risk = 0.25
            if file_access_count is not None and file_access_count > 50:
                risk += 0.25
            if login_hour is not None and (login_hour < 6 or login_hour > 22):
                risk += 0.15
            if payload_size is not None and payload_size > 2_000_000:
                risk += 0.10
            return ("UNKNOWN", float(min(risk, 0.85)))

        pred = self.model.predict(x)[0]  # -1 anomaly, 1 normal
        normality = float(self.model.decision_function(x)[0])  # higher => more normal

        # map normality to risk [0,1]
        risk = 1.0 / (1.0 + np.exp(5 * normality))
        label = "ANOMALY" if pred == -1 else "NORMAL"
        return (label, float(np.clip(risk, 0.0, 1.0)))