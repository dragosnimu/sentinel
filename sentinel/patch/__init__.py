"""Patch plan generation, validation and execution.

The split matters: `planner` asks a model for a plan, `validator` decides
deterministically whether it is safe, and `runner` executes it through the root
executor. A model's output never reaches `runner` without passing `validator`.
"""
