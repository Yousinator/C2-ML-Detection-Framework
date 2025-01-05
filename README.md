## Folder structure for the Classical ML Processes for ScytheEX

```bash
malware-model-training/
│
├── data/
│   ├── raw/
│       ├── malware_1/
│           └── [raw data files for malware_1]
│       ├── malware_2/
│           └── [raw data files for malware_2]
│   ├── processed/
│       ├── malware_1/
│           └── [processed data files for malware_1]
│       ├── malware_2/
│           └── [processed data files for malware_2]
│   └── metadata/
│       ├── malware_1/
│           └── [metadata files for malware_1]
│       ├── malware_2/
│           └── [metadata files for malware_2]
│
├── models/
│   ├── trained/
│       ├── malware_1/
│           └── [trained models for malware_1]
│       ├── malware_2/
│           └── [trained models for malware_2]
│   ├── checkpoints/
│       ├── malware_1/
│           └── [model checkpoints for malware_1]
│       ├── malware_2/
│           └── [model checkpoints for malware_2]
│
├── notebooks/
│   ├── data_preprocessing/
│       ├── malware_1/
│           └── preprocessing.ipynb
│       ├── malware_2/
│           └── preprocessing.ipynb
│   ├── model_training/
│       ├── malware_1/
│           └── training.ipynb
│       ├── malware_2/
│           └── training.ipynb
│   ├── model_evaluation/
│       ├── malware_1/
│           └── evaluation.ipynb
│       ├── malware_2/
│           └── evaluation.ipynb
│   └── experiments/
│       ├── malware_1/
│           └── experiment.ipynb
│       ├── malware_2/
│           └── experiment.ipynb
│
├── variables/
│   ├── scalers/
│       ├── malware_1/
│           └── scaler.pkl
│       ├── malware_2/
│           └── scaler.pkl
│   ├── encoders/
│       ├── malware_1/
│           └── encoder.pkl
│       ├── malware_2/
│           └── encoder.pkl
│   └── other/
│       ├── malware_1/
│           └── other.pkl
│       ├── malware_2/
│           └── other.pkl
│
└── [other project files, e.g., README.md, requirements.txt, etc.]
```