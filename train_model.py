"""
train_model.py — ฝึกและประเมินโมเดล NLP ตรวจจับ SMS มิจฉาชีพ (Python / scikit-learn)

วิธีประเมิน (ตามคำแนะนำของอาจารย์)
  - ตัดข้อความซ้ำก่อน (ชุดข้อมูลเดิมซ้ำ 301 จาก 700 รายการ)
  - Stratified k-fold cross-validation (k = 4: ทดสอบทีละ 25% เทรนด้วย 75% แล้วหมุนจนครบ)
    ทำซ้ำ 5 รอบด้วยการสลับข้อมูลต่างกัน แล้วรายงาน ค่าเฉลี่ย ± SD ของทุกตัวชี้วัด
  - ตัดสินแบบสองคลาส: 1 = มิจฉาชีพ (ไม่น่าเชื่อถือ), 0 = ข้อความปกติ (น่าเชื่อถือ) ที่เกณฑ์ความน่าจะเป็น 0.5
  - ทดสอบกับข้อความนอกชุดข้อมูล (external_test_100.csv) ผ่าน evaluate_external.py

ผลลัพธ์
  model/scam_model.joblib     โมเดลที่ใช้ใน server.py (ฝึกด้วยข้อมูลที่ไม่ซ้ำทั้งหมด)
  model/metrics.json          ตัวเลขที่หน้า model.html แสดง
  model/predictions_cv.csv    คำทายแบบ out-of-fold ของข้อความทุกข้อความ (ไว้ดูตัวอย่างถูก/ผิด)

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
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import RepeatedStratifiedKFold, StratifiedKFold, cross_val_predict, cross_validate
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC

DATA_PATH = "thai_scam_sms_dataset.csv"
OUT_DIR = "model"
SEED = 42
K = 4          # 4-fold = ทดสอบ 25% / เทรน 75%
REPEATS = 5
SCORING = {"accuracy": "accuracy", "precision": "precision", "recall": "recall", "f1": "f1", "roc_auc": "roc_auc"}


def normalize(text):
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def load_dataset(path=DATA_PATH):
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    seen, texts, labels = set(), [], []
    for r in rows:
        key = normalize(r["text"])
        if key in seen:
            continue
        seen.add(key)
        texts.append(r["text"].strip())
        labels.append(int(r["label"]))
    return texts, np.array(labels), len(rows)


def new_vectorizer():
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=2, sublinear_tf=True, lowercase=True)


def candidates():
    return {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.3),
        "Logistic Regression": LogisticRegression(C=10, max_iter=2000, random_state=SEED),
        "Support Vector Machine (LinearSVC)": CalibratedClassifierCV(LinearSVC(C=1.0, random_state=SEED), cv=3),
        "Random Forest Classifier": RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1),
        "Neural Network (MLP)": MLPClassifier(hidden_layer_sizes=(64,), alpha=1e-3, max_iter=500, random_state=SEED),
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
            if len(t) < 3 or " " in t or any(t in c or c in t for c in chosen):
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
    print(f"ประเมินด้วย Stratified {K}-fold x {REPEATS} รอบ ({K * REPEATS} ครั้งต่อโมเดล)\n")

    rskf = RepeatedStratifiedKFold(n_splits=K, n_repeats=REPEATS, random_state=SEED)
    oof_split = StratifiedKFold(n_splits=K, shuffle=True, random_state=SEED)

    results, oof = [], {}
    for name in candidates():
        pipe = make_pipeline(new_vectorizer(), candidates()[name])
        cv = cross_validate(pipe, texts, y, cv=rskf, scoring=SCORING, n_jobs=-1)
        m = {"name": name}
        for key in SCORING:
            vals = cv["test_" + key]
            m[key] = float(vals.mean())
            m[key + "_std"] = float(vals.std())
        # คำทายแบบ out-of-fold (ข้อความแต่ละข้อความถูกทายโดยโมเดลที่ไม่เคยเห็นมัน) ใช้ทำ confusion matrix
        prob = cross_val_predict(make_pipeline(new_vectorizer(), candidates()[name]), texts, y, cv=oof_split, method="predict_proba")[:, 1]
        pred = (prob >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        m["confusion"] = [[int(tn), int(fp)], [int(fn), int(tp)]]
        results.append(m)
        oof[name] = (pred, prob)
        print(f"{name:38s} acc={m['accuracy']:.3f}±{m['accuracy_std']:.3f} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f}±{m['f1_std']:.3f} AUC={m['roc_auc']:.3f}")

    # โมเดลที่ใช้งานจริง: เลือกจากโมเดลที่อธิบายได้ (Logistic Regression / Naive Bayes) ที่ F1 เฉลี่ยสูงสุด
    explainable = [r for r in results if r["name"] in ("Logistic Regression", "Multinomial Naive Bayes")]
    best = max(explainable, key=lambda r: (round(r["f1"], 4), r["name"] == "Logistic Regression"))
    deployed = make_pipeline(new_vectorizer(), candidates()[best["name"]]).fit(texts, y)

    os.makedirs(OUT_DIR, exist_ok=True)
    joblib.dump(deployed, os.path.join(OUT_DIR, "scam_model.joblib"))

    pred, prob = oof[best["name"]]
    with open(os.path.join(OUT_DIR, "predictions_cv.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "pred", "scam_probability", "correct"])
        for t, a, b, p in zip(texts, y, pred, prob):
            w.writerow([t, int(a), int(b), round(float(p), 4), int(a == b)])

    metrics = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dataset": {"file": DATA_PATH, "n_raw": n_raw, "n_unique": n_unique, "n_duplicates": n_raw - n_unique,
                    "n_scam": int(y.sum()), "n_ham": int((y == 0).sum())},
        "evaluation": {"method": f"Stratified {K}-fold cross-validation x {REPEATS} repeats", "k": K, "repeats": REPEATS,
                       "n_folds_total": K * REPEATS, "threshold": 0.5,
                       "classes": {"1": "scam (ไม่น่าเชื่อถือ)", "0": "ham (น่าเชื่อถือ)"}},
        "features": "TF-IDF character n-gram (char_wb, 2-4)",
        "deployed": best["name"],
        "models": results,
        "top_terms": top_terms(deployed),
    }

    import evaluate_external
    # ฝึกทุกอัลกอริทึมด้วยข้อมูลที่ไม่ซ้ำทั้งหมด แล้วทดสอบกับชุดนอกข้อมูล (ผลนี้ไม่ใช้เลือกโมเดล)
    all_fitted = {n: make_pipeline(new_vectorizer(), c).fit(texts, y) for n, c in candidates().items()}
    metrics["external"] = evaluate_external.run(deployed, OUT_DIR, all_models=all_fitted)

    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    print(f"\nใช้งานจริง: {best['name']} | บันทึก {OUT_DIR}/ ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()
