"""
evaluate_external.py — ทดสอบโมเดลกับข้อความ "นอกชุดข้อมูล" ที่โมเดลไม่เคยเห็น

ไฟล์ข้อมูล (เลือกไฟล์แรกที่มีข้อความอยู่)
  1) external_test_100.csv   ชุดทดสอบ 100 ข้อความที่เก็บเพิ่ม  คอลัมน์: id,text,label   (label: 1 = มิจฉาชีพ, 0 = ปกติ)
  2) external_check.csv      ข้อความตัวอย่าง 15 ข้อความ (ใช้ชั่วคราวระหว่างที่ยังไม่มีชุด 100)

ข้อห้าม: ห้ามเอาข้อความในไฟล์เหล่านี้ไปใส่ในชุดฝึก (thai_scam_sms_dataset.csv) ไม่งั้นผลจะไม่เป็นกลาง

รันแยกได้:  python evaluate_external.py
ผลลัพธ์: model/external_predictions.json (ข้อความ + เฉลย + คำทาย) และคืนค่าสรุปให้ train_model.py
"""
import csv
import json
import os

import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

CANDIDATES = ["external_test_100.csv", "external_check.csv"]


def load_external():
    for path in CANDIDATES:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8-sig", newline="") as f:
            rows = [r for r in csv.DictReader(f) if r.get("text", "").strip() != ""]
        if rows:
            return path, rows
    return None, []


def run(model, out_dir="model"):
    path, rows = load_external()
    if not rows:
        print("ไม่พบไฟล์ข้อความนอกชุดข้อมูล")
        return None
    texts = [r["text"].strip() for r in rows]
    y = [int(r["label"]) for r in rows]
    prob = model.predict_proba(texts)[:, 1]
    pred = [int(p >= 0.5) for p in prob]
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    items = [{"id": r.get("id") or str(i + 1), "text": t, "label": a, "pred": b,
              "scam_probability": round(float(p), 4), "correct": bool(a == b)}
             for i, (r, t, a, b, p) in enumerate(zip(rows, texts, y, pred, prob))]
    summary = {
        "file": path, "n": len(items), "n_correct": sum(i["correct"] for i in items),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "external_predictions.json"), "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "items": items}, f, ensure_ascii=False)
    print(f"ข้อความนอกชุดข้อมูล ({path}): ถูก {summary['n_correct']}/{summary['n']}  "
          f"acc={summary['accuracy']:.3f} P={summary['precision']:.3f} R={summary['recall']:.3f} F1={summary['f1']:.3f}")
    return summary


if __name__ == "__main__":
    run(joblib.load(os.path.join("model", "scam_model.joblib")))
