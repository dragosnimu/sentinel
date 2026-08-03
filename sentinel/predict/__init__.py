"""Prediction: statistical baselines, seasonality, and the anomaly signal.

No ML. A robust seasonal baseline (median + MAD per hour-of-week) with a
mandatory 14-day warm-up — explainable, cheap, and honest about what it does
not yet know. See baseline.py.
"""
