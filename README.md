# Phishing URL Detection — Model Validation & Real-World Results

This section showcases how the LightGBM + lexical/TF-IDF model performs on both **benchmarked phishing URLs (PhishTank)** and **real-world phishing attempts** (phonetic lookalikes, SMS attacks).  

## Validation Against PhishTank

We validated the model using URLs listed in [PhishTank](https://phishtank.org/).  
Our predictions match PhishTank’s ground-truth verdicts with high confidence.

<img width="2936" height="340" alt="image" src="https://github.com/user-attachments/assets/30f30af9-b6a1-4f22-be41-2c5fe404037b" />
<img width="1600" height="194" alt="image" src="https://github.com/user-attachments/assets/61522722-2050-4d3e-b264-42b323e0b571" />
<img width="1600" height="194" alt="image" src="https://github.com/user-attachments/assets/d510433a-3d82-4646-8a34-efdf93722c87" />
<img width="542" height="216" alt="image" src="https://github.com/user-attachments/assets/933b85a7-f53c-4a7f-871b-c1514d1e2adb" />
<img width="570" height="216" alt="image" src="https://github.com/user-attachments/assets/702c4999-dad2-495a-b7ef-9afc7e2945a1" />
<img width="678" height="602" alt="image" src="https://github.com/user-attachments/assets/e0bac9d0-6cd0-4db9-a783-d2e89095e2cc" />

🟢 Legitimate websites were classified correctly.  
🔴 Phishing websites were flagged with near-perfect confidence.

## Real-World Testing

###   Phonetic & Hyphenated Phishing
The model successfully detected *lookalike domains* (phonetic and hyphenated variants) as phishing attempts.


<img width="540" height="1158" alt="image" src="https://github.com/user-attachments/assets/d65cb720-6db8-4868-8ebb-38aa1c751c73" />


Both variants (`easycash.id`, `easy-cash.id`) are caught as phishing.


### SMS Phishing Example

<img width="638" height="216" alt="image" src="https://github.com/user-attachments/assets/18f206a2-a7ec-4cd7-89f6-fc6c276247e7" />


Model prediction:
![Uploading image.png…]()


The model correctly flagged this SMS phishing attempt with **near-absolute certainty**.


