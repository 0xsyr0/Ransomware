# 🛡️ Ransomware Threat Intelligence Collection



## 📖 About

This repository is a structured and continuously evolving collection of intelligence on various ransomware families and the threat actors (TAs) behind them. It contains ransom notes, analysis tools, YARA rules, indicators of compromise (IoCs), and other resources aimed at:

- Identifying ransomware strains and activity
- Understanding their behavior, tooling, and impact
- Clustering and tracking threat actors

This resource supports analysts, researchers, and defenders in their efforts to combat ransomware attacks.



## 📁 Repository Structure

The repository is organized by ransomware family or threat actor, with each folder containing relevant files. Below is an example of the structure:

```
Ransomware/  
├── Babuk/  
│   ├── tools/  
│   └── Babuk.yar  
└── HsHarada/  
    ├── Unlocker/  
    ├── ransom_notes/  
    ├── tools/  
    ├── HsHarada.yar  
    ├── HsHarada_samples.txt  
    ├── IoCs.txt  
    ├── attackers.txt  
    └── readme.txt  
```

### 📂 Contents

- **`ransom_notes/`** – Unique ransom note samples.
- **`tools/`** – Scripts or utilities for ransomware analysis, decryption, or forensic purposes.
- **`*.yar`** – YARA rules to detect specific ransomware variants.
- **`*_samples.txt`** – Hashes of discovered samples, compilation timestamps, and metadata.
- **`IoCs.txt`** – IPs, domains, file paths, and hashes associated with the TA.
- **`attackers.txt`** – Contact details or handles used by the threat actors for communication.
- **`readme.txt`** – External references, such as blog posts or threat reports.



## ⚖️ License

This project is licensed under the [Apache License 2.0](LICENSE).
