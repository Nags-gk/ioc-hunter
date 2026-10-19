"""Domain-generation-algorithm (DGA) classifier.

Character 2-4-gram TF-IDF + logistic regression, plus entropy and digit features.
Trained on two DGA families (random characters, hex hashes) and a benign list, then
tested on a held-out benign split and a third family it never saw: dictionary DGAs
built from English words, which is the hard case for character models.
"""
from __future__ import annotations

import math
import random
from collections import Counter
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from .scenario import dga_family_a, dga_family_b, dga_family_c

BENIGN_FILE = Path(__file__).resolve().parent / "benign_domains.txt"


def label(domain: str) -> str:
    """The registrable label: 'cdn.example.co.uk' -> 'example', 'abc.top' -> 'abc'."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


def _dense(labels):
    return csr_matrix(np.array([[entropy(x), len(x) / 20, sum(ch.isdigit() for ch in x) / max(1, len(x)),
                                 sum(ch in "aeiou" for ch in x) / max(1, len(x))] for x in labels]))


class DGAModel:
    def __init__(self):
        self.vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2, sublinear_tf=True)
        self.clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")

    def fit(self, domains, y):
        labs = [label(d) for d in domains]
        X = hstack([self.vec.fit_transform(labs), _dense(labs)])
        self.clf.fit(X, y)
        return self

    def score(self, domains) -> np.ndarray:
        labs = [label(d) for d in domains]
        return self.clf.predict_proba(hstack([self.vec.transform(labs), _dense(labs)]))[:, 1]


def benign_domains() -> list[str]:
    return [line.strip() for line in BENIGN_FILE.read_text().splitlines() if line.strip() and not line.startswith("#")]


def train_and_evaluate(seed: int = 3) -> tuple[DGAModel, dict]:
    ben = benign_domains()
    r = random.Random(seed)
    r.shuffle(ben)
    cut = int(len(ben) * 0.7)
    tr_b, te_b = ben[:cut], ben[cut:]
    tr_a, te_a = dga_family_a(100, 400), dga_family_a(200, 200)
    tr_h, te_h = dga_family_b(101, 400), dga_family_b(201, 200)
    te_c = dga_family_c(202, 200)
    m = DGAModel().fit(tr_b + tr_a + tr_h, [0] * len(tr_b) + [1] * (len(tr_a) + len(tr_h)))
    thr = 0.5
    sb, sa, sh, sc = m.score(te_b), m.score(te_a), m.score(te_h), m.score(te_c)
    metrics = dict(
        benign_train=len(tr_b), benign_test=len(te_b), threshold=thr,
        benign_false_positive_rate=round(float((sb >= thr).mean()), 4),
        recall_random_chars_seen_family=round(float((sa >= thr).mean()), 4),
        recall_hex_seen_family=round(float((sh >= thr).mean()), 4),
        recall_dictionary_unseen_family=round(float((sc >= thr).mean()), 4),
        auc_dictionary_vs_benign=round(float(roc_auc_score([0] * len(sb) + [1] * len(sc), np.r_[sb, sc])), 4),
        false_positives=[d for d, s in zip(te_b, sb, strict=True) if s >= thr][:10],
    )
    return m, metrics
