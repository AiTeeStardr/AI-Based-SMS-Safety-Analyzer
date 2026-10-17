"""ตัวโหลดโมเดลและฟังก์ชันทำนายที่ใช้ร่วมกันระหว่าง server.py (รันในเครื่อง) และ api/analyze.py (Vercel)"""
import os

import joblib

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model", "scam_model.joblib")
MAX_TEXT = 1000

try:
    MODEL = joblib.load(MODEL_PATH)
    LOAD_ERROR = None
except Exception as e:  # ยังไม่ได้ train หรือเวอร์ชัน scikit-learn ไม่ตรง
    MODEL = None
    LOAD_ERROR = str(e)


def explain(text, k=5):
    """n-gram ที่ผลักให้ข้อความนี้ไปทางมิจฉาชีพมากที่สุด (น้ำหนักฟีเจอร์ x ค่า TF-IDF)"""
    vec, clf = MODEL.steps[0][1], MODEL.steps[-1][1]
    if hasattr(clf, "coef_"):
        w = clf.coef_[0]
    elif hasattr(clf, "feature_log_prob_"):
        w = clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
    else:
        return []
    contrib = vec.transform([text]).multiply(w).tocoo()
    names = vec.get_feature_names_out()
    chosen = []
    for i, v in sorted(zip(contrib.col, contrib.data), key=lambda p: -p[1]):
        if v <= 0:
            break
        t = names[i].strip()
        if len(t) < 3 or " " in t or any(t in c or c in t for c in chosen):
            continue
        chosen.append(t)
        if len(chosen) == k:
            break
    return chosen


def predict(text):
    text = text[:MAX_TEXT]
    prob = float(MODEL.predict_proba([text])[0][1])
    return {
        "label": "scam" if prob >= 0.5 else "ham",
        "scam_probability": round(prob, 4),
        "top_terms": explain(text) if prob >= 0.5 else [],
        "model": "scam_model.joblib",
    }
