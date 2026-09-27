"""Barrier - owned security intelligence for AI agents.

Barrier sits between what your agents learn and what your agents do. It screens
three things: what agents are allowed to remember (the memory gate), what
behaviours they are allowed to reuse (the procedure gate), and what they are
allowed to act on (the operation gate).

Nothing in this package fabricates a measurement. Evaluation numbers shown in
the dashboard come from `data/eval.json`, which only exists after
`training/evaluate.py` has actually run.
"""

__version__ = "0.1.0"
