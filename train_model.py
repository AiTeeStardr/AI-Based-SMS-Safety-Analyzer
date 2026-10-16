"""
train_model.py — ฝึกและประเมินโมเดล NLP ตรวจจับ SMS มิจฉาชีพ (Python / scikit-learn)

ต่างจาก scam_detection_pipeline.py เดิม 3 จุด เพื่อให้ผลทดสอบเชื่อถือได้
  1) ตัดข้อความซ้ำก่อนแบ่งชุดฝึก/ทดสอบ  (ชุดข้อมูลเดิมซ้ำ 301 จาก 700 รายการ ทำให้ได้ 100% เกินจริง)
  2) ใช้ character n-gram (char_wb 2-4) แทนการตัดคำด้วย regex เพราะ regex ตัดภาษาไทยผิด
     (ได้ "ไม", "สม", "ทธ" เป็นฟีเจอร์) และ char n-gram ไม่ต้องพึ่งตัวตัดคำ
  3) รายงาน confusion matrix และ cross-validation แบบแบ่งชั้น (stratified) บนข้อมูลที่ไม่ซ้ำ

ผลลัพธ์
  model/scam_model.joblib   โมเดลที่ใช้ใน server.py
  model/metrics.json        ตัวเลขทั้งหมดที่หน้า model.html แสดง

รัน:  python train_model.py
"""
import csv
import json
import os
import re
import time

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC

DATA_PATH = "thai_scam_sms_dataset.csv"
EXTERNAL_PATH = "external_check.csv"
OUT_DIR = "model"
SEED = 42


def normalize(text):
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def load_dataset(path=DATA_PATH):
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    n_raw = len(rows)
    seen, texts, labels = set(), [], []
    for r in rows:
        key = normalize(r["text"])
        if key in seen:
            continue
        seen.add(key)
        texts.append(r["text"].strip())
        labels.append(int(r["label"]))
    return texts, np.array(labels), n_raw


def new_vectorizer():
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=2, sublinear_tf=True, lowercase=True)


def candidates():
    return {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.3),
        "Logistic Regression": LogisticRegression(C=10, max_iter=2000, random_state=SEED),
        "Support Vector Machine (LinearSVC)": CalibratedClassifierCV(LinearSVC(C=1.0, random_state=SEED), cv=3),
        "Random Forest Classifier": RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1),
    }


def score_of(pipe, X_test, y_test):
    pred = pipe.predict(X_test)
    prob = pipe.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, prob)),
        "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def top_terms(pipe, k=15):
    """n-gram ที่ดันให้เป็นมิจฉาชีพ / ข้อความปกติ มากที่สุด (เฉพาะโมเดลเชิงเส้น)"""
    vec, clf = pipe.steps[0][1], pipe.steps[-1][1]
    names = vec.get_feature_names_out()
    if hasattr(clf, "coef_"):
        w = clf.coef_[0]
    elif hasattr(clf, "feature_log_prob_"):
        w = clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
    else:
        return {"scam": [], "ham": []}

    def pick(order):
        chosen = []
        for i in order:
            t = names[i].strip()
            if len(t) < 3 or " " in t:
                continue
            if any(t in c or c in t for c in chosen):
                continue
            chosen.append(t)
            if len(chosen) == k:
                break
        return chosen

    order = np.argsort(w)
    return {"scam": pick(order[::-1]), "ham": pick(order)}


def main():
    t0 = time.time()
    texts, y, n_raw = load_dataset()
    n_unique = len(texts)
    print(f"ข้อความทั้งหมด {n_raw} | ไม่ซ้ำ {n_unique} | มิจฉาชีพ {int(y.sum())} | ปกติ {int((y == 0).sum())}")

    X_train, X_test, y_train, y_test = train_test_split(texts, y, test_size=0.2, random_state=SEED, stratify=y)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)

    results, fitted = [], {}
    for name, clf in candidates().items():
        pipe = make_pipeline(new_vectorizer(), clf)
        pipe.fit(X_train, y_train)
        m = score_of(pipe, X_test, y_test)
        cv = cross_val_score(make_pipeline(new_vectorizer(), candidates()[name]), texts, y, cv=skf, scoring="f1")
        m.update({"name": name, "cv_f1_mean": float(cv.mean()), "cv_f1_std": float(cv.std())})
        results.append(m)
        fitted[name] = pipe
        print(f"{name:38s} acc={m['accuracy']:.3f} f1={m['f1']:.3f} auc={m['roc_auc']:.3f} cv_f1={cv.mean():.3f}±{cv.std():.3f}")

    # เลือกโมเดลที่ใช้งานจริง จากโมเดลที่อธิบายได้ (มีน้ำหนักฟีเจอร์): F1 สูงสุด เสมอกันเลือก CV F1 แล้วเลือก Logistic Regression
    explainable = [r for r in results if r["name"] in ("Logistic Regression", "Multinomial Naive Bayes")]
    best = max(explainable, key=lambda r: (round(r["f1"], 4), round(r["cv_f1_mean"], 4), r["name"] == "Logistic Regression"))
    deployed = fitted[best["name"]]

    # ทดสอบกับข้อความนอกชุดข้อมูล (เขียนเอง/ของจริง 15 ข้อความ) ที่โมเดลไม่เคยเห็น
    external = []
    if os.path.exists(EXTERNAL_PATH):
        with open(EXTERNAL_PATH, encoding="utf-8-sig", newline="") as f:
            ext = list(csv.DictReader(f))
        probs = deployed.predict_proba([r["text"] for r in ext])[:, 1]
        for r, p in zip(ext, probs):
            external.append({"id": r["id"], "label": int(r["label"]), "scam_probability": round(float(p), 3),
                             "correct": bool((p >= 0.5) == (int(r["label"]) == 1))})
        print(f"ข้อความนอกชุดข้อมูล: ถูก {sum(e['correct'] for e in external)}/{len(external)}")

    os.makedirs(OUT_DIR, exist_ok=True)
    joblib.dump(deployed, os.path.join(OUT_DIR, "scam_model.joblib"))
    metrics = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dataset": {"file": DATA_PATH, "n_raw": n_raw, "n_unique": n_unique, "n_duplicates": n_raw - n_unique,
                    "n_scam": int(y.sum()), "n_ham": int((y == 0).sum()),
                    "n_train": len(X_train), "n_test": len(X_test)},
        "features": "TF-IDF character n-gram (char_wb, 2-4)",
        "deployed": best["name"],
        "models": results,
        "top_terms": top_terms(deployed),
        "external": {"file": EXTERNAL_PATH, "n": len(external), "n_correct": sum(e["correct"] for e in external), "items": external},
    }
    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    print(f"\nใช้งานจริง: {best['name']} | บันทึก {OUT_DIR}/scam_model.joblib และ {OUT_DIR}/metrics.json ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()
