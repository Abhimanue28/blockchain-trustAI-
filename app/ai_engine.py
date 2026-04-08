import numpy as np
from sklearn.ensemble import IsolationForest


class AIThreatModel:

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.15,
            random_state=42
        )
        self.is_trained = False

    def _vectorize(self, login_hour, file_access_count, payload_size):

        lh = 12 if login_hour is None else int(login_hour)
        fac = 0 if file_access_count is None else int(file_access_count)
        ps = 0 if payload_size is None else int(payload_size)

        return np.array(
            [[
                lh / 23.0,
                fac / 100.0,
                ps / 5000.0
            ]],
            dtype=float
        )

    def train(self, samples):
        clean_samples = []

        for s in samples:
            if s is None or len(s) != 3:
                continue

            login_hour, file_access_count, payload_size = s
            clean_samples.append((login_hour, file_access_count, payload_size))

        if len(clean_samples) < 10:
            self.is_trained = False
            return

        X = np.vstack([self._vectorize(*s) for s in clean_samples])
        self.model.fit(X)
        self.is_trained = True

    def score(self, login_hour, file_access_count, payload_size):
        x = self._vectorize(login_hour, file_access_count, payload_size)

        # Cold start heuristic before enough training data exists
        if not self.is_trained:
            risk = 0.10

            if file_access_count is not None:
                if file_access_count > 40:
                    risk += 0.35
                elif file_access_count > 15:
                    risk += 0.15

            if login_hour is not None:
                if login_hour < 6 or login_hour > 22:
                    risk += 0.25

            if payload_size is not None:
                if payload_size > 1000:
                    risk += 0.25
                elif payload_size > 300:
                    risk += 0.10

            risk = float(np.clip(risk, 0.0, 1.0))

            if risk >= 0.65:
                return ("ANOMALY", risk)
            return ("NORMAL", risk)

        pred = self.model.predict(x)[0]  # -1 anomaly, 1 normal
        normality = float(self.model.decision_function(x)[0])  # higher => more normal

        # Convert normality into risk score
        risk = 1.0 / (1.0 + np.exp(8 * normality))
        risk = float(np.clip(risk, 0.0, 1.0))

        label = "ANOMALY" if pred == -1 else "NORMAL"
        return (label, risk)