<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-PyTorch-red?style=for-the-badge&logo=pytorch" />
  <img src="https://img.shields.io/badge/Package_Manager-Poetry-8c52ff?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Tracking-MLflow-orange?style=for-the-badge" />
  <img src="https://img.shields.io/github/last-commit/Yousinator/C2-ML-Detection-Framework?style=for-the-badge" />
</p>

---

# C2-ML-Detection-Framework

A modular, ML-powered framework designed to detect command-and-control (C2) malware using network traffic data. Developed as part of a research project targeting the detection of malware through sequence-aware deep learning models (e.g., LSTM).

This framework is focused on experimentation, extensibility, and reproducibility — with full MLflow support and Python environment management via Poetry.

---

## Directory Structure

```bash
malware-model-training/
│
├── data/
│   ├── raw/
│       ├── csv/
│           └── [raw data files for malware in csv]
│       ├── pcap/
│           └── [raw data files for malware in pcap]
│   ├── processed/
│       ├── malware_1.csv
│       ├── malware_2.csv
│   └── labelled/
│       ├── malware_1.csv
│       ├── malware_2.csv
│
├── models/
│   ├── malware_1/
│       └── [trained models for malware_1]
│   ├── malware_2/
│       └── [trained models for malware_2]
│
├── notebooks/
│   ├── data_processing/
│       ├── malware_1.ipynb
│       ├── malware_2.ipynb
│   ├── modeling/
│       ├── malware_1.ipynb
│       ├── malware_2.ipynb
│   ├── data_labelling/
│       ├── malware_1.ipynb
│       ├── malware_2.ipynb
│   ├── data_parsing/
│       ├── malware_1.py
│       ├── malware_2.py
│
├── variables/
│       ├── malware_1/
│           └── scaler.pkl
│       ├── malware_2/
│           └── scaler.pkl
│
└── [other project files, e.g., README.md, requirements.txt, etc.]
```

---

## Features

- End-to-end ML pipeline for malware traffic detection
- Reproducible experiments with [MLflow](https://mlflow.org/)
- Dependency isolation using [Poetry](https://python-poetry.org/)
- Real-world datasets including **Dridex** and **Emotet**
- Deep learning models (LSTM-based) for temporal pattern recognition

---

## Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Yousinator/C2-ML-Detection-Framework.git
   cd C2-ML-Detection-Framework
   ```

2. **Install Poetry (if you haven’t)**

   ```bash
   curl -sSL https://install.python-poetry.org | python3 -

   ```

3. **Install Dependencies**

   ```bash
   poetry install

   ```

4. **Activate the Virtual Environment**

   ```bash
   poetry shell

   ```

## Notebooks

All experimentation is done through notebooks inside the `notebooks/` directory. Each notebook is self-contained and includes:

- Data Parsing
- Data loading and preprocessing
- Feature engineering
- Model training and evaluation

MLflow artifacts and metrics will be logged automatically to the `mlruns/` folder.

## Datasets

The framework supports labeled datasets for C2 malware such as:

- Dridex C2 traffic
- Emotet C2 traffic

Data is under the `data/` directory. Structure and preprocessing steps are detailed in the relevant Jupyter notebooks under `notebooks/`.

## Model Overview

- **Core model**: LSTM-based malware traffic classifier
- **Input features**: Sequence of flow-level and packet-level statistics
- **Output**: Binary label (malicious / benign)

## Citation

If you use this framework in your research or project, please consider citing:

```bash
@misc{musabeh2025c2ml,
  author       = {Yousef Musabeh},
  title        = {A Machine Learning Framework for Detecting Command-and-Control Malware via Network Behavior},
  year         = {2025},
  url          = {https://github.com/Yousinator/C2-ML-Detection-Framework}
}
```

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
Let me know if you want sections for **Contributing**, **Environment Variables**, or more advanced usage examples!
