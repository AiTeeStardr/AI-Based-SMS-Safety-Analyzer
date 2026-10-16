# 🛡️ AI ตรวจจับข้อความมิจฉาชีพและ SMS หลอกลวง (Scam & Phishing Detector)
### โครงงานการเรียนรู้ของเครื่องและการประมวลผลภาษาธรรมชาติ (NLP & Supervised Learning)

🌐 **ลิงก์หน้าเว็บออนไลน์ 24 ชม. (เปิดใช้งานได้ทันที):** [https://thai-scam-ai.surge.sh](https://thai-scam-ai.surge.sh)  
📑 **เล่มรายงานฉบับเต็ม:** [PROJECT_REPORT.md](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/PROJECT_REPORT.md)

---

## 📁 ไฟล์สำคัญในโปรเจ็กต์นี้:
1. **[index.html](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/index.html)**: หน้าเว็บแอปพลิเคชันระบบตรวจจับมิจฉาชีพ รองรับทุกอุปกรณ์และมีโหมดตัวหนังสือใหญ่สำหรับผู้สูงอายุ
2. **[scam_detection_pipeline.py](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/scam_detection_pipeline.py)**: โค้ดไพธอนรันโมเดล NLP (TF-IDF + Naive Bayes, SVM, Logistic Regression, Random Forest)
3. **[Scam_SMS_Detection_Project.ipynb](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/Scam_SMS_Detection_Project.ipynb)**: ไฟล์ Jupyter Notebook พร้อมคำอธิบายสำหรับเปิดใน VS Code หรือ Google Colab
4. **[thai_scam_sms_dataset.csv](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/thai_scam_sms_dataset.csv)**: ชุดข้อมูลข้อความภาษาไทย 700 ตัวอย่าง
5. **[scam_model_evaluation.csv](file:///c:/Users/%E0%B8%9E%E0%B8%87%E0%B8%A8%E0%B8%81%E0%B8%A3/Downloads/111111111111111111111/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B9%80%E0%B8%82%E0%B8%A1%E0%B8%B4%E0%B8%81%E0%B8%B2/%E0%B8%87%E0%B8%B2%E0%B8%99%E0%B8%81%E0%B8%B8%E0%B9%80%E0%B8%AD%E0%B8%87/scam_model_evaluation.csv)**: ตารางเปรียบเทียบผลลัพธ์โมเดล
6. **โฟลเดอร์ `charts/`**: แผนภาพการประเมินผลความละเอียดสูงสำหรับจัดทำสไลด์และรายงาน
