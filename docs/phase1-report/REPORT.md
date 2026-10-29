# A Major Project Report (Phase-I)
## On
# Intelligent Network Intrusion Detection System

**Submitted in partial fulfillment of the requirement for the award of the degree of**  
**BACHELOR OF TECHNOLOGY**  
**Session 2026-27**  
**in**  
**Computer Science and Engineering**

### Submitted By:
* **Sneha Singh** (2410031243)
* **Sudhanshu Sharma** (2410031280)
* **Ayush Kumar** (2410031217)
* **Tanishq Kumar** (2410031443)

### Under the Guidance of:
**Dr. Prabhu K**  
School of Computer Science and Engineering  
**IILM University, Greater Noida**  
*August, 2026*

---

## Candidate's Declaration

We hereby certify that the work presented in the Phase-I report of the project entitled **“Intelligent Network Intrusion Detection System”**, in partial fulfillment of the requirements for the degree of Bachelor of Technology in the School of Computing Science and Engineering, IILM University, Greater Noida, is an original work carried out by us under the supervision of Dr. Prabhu K, School of Computing Science and Engineering, IILM University, Greater Noida.

The work presented in this Phase-I report has not been submitted by us for the award of any other degree or qualification at this or any other institution.

* Sneha Singh (2410031243)
* Sudhanshu Sharma (2410031280)
* Ayush Kumar (2410031217)
* Tanishq Kumar (2410031443)

---

## Table of Contents

| Section | Title |
|---|---|
| — | **Abstract** |
| 1 | **Problem Definition** |
| 2 | **Literature Survey** |
| | 2.1 From Traditional IDS to Intelligent IDS |
| | 2.2 Machine Learning and Deep Learning: Teaching the IDS to Recognise Patterns |
| | 2.3 Transformers: Looking at the Bigger Picture |
| | 2.4 The Privacy Problem: Why Centralised Learning Starts to Break |
| | 2.5 Federated Learning: Smarter Collaboration, New Problems |
| | 2.6 Lightweight IDS: Putting Intelligence Where the Traffic is |
| | 2.7 Imbalanced Traffic when Accuracy can be false |
| | 2.8 Explainability and Robustness |
| | 2.9 Adaptability: The Network never stands still |
| | 2.10 Connected Research Gaps |
| | 2.11 Overall Direction for an IDS |
| | 2.12 Conclusion of the Survey |
| 3 | **Objectives** |
| 4 | **Scope** |
| 5 | **Feasibility Study** |
| | 5.1 Technical Feasibility |
| | 5.2 Operational Feasibility |
| | 5.3 Economic Feasibility |
| | 5.4 Schedule Feasibility |
| — | **References** |

---

## Abstract

Due to the fast development of interconnected networks and IT-solutions, the level of complexity of the cyberattacks has significantly increased, and it is necessary to find innovative solutions for detecting attacks. This project suggests the development of an Intelligent Network Intrusion Detection System (INIDS) based on application of machine learning methods in order to classify and detect attacks on the network. It includes monitoring of network traffic, extraction of network features like connection time, protocol used, number of packets etc., in order to differentiate normal and abnormal activities of the network. Machine learning models are trained on the basis of the dataset representing network traffic, and attacks of different kinds like Denial of Service, Probing and Access are detected. The suggested IIDS allows avoiding false detections and providing security administrators with real-time alerts.

The proposed methodology involves a structured framework involving data acquisition, data preprocessing, feature extraction, model training, and attack classification. Network data obtained is cleaned and formatted appropriately in order to feed into machine learning algorithms in an effort to detect patterns related to malicious activity. This system is designed to continuously monitor network traffic and create an alert whenever suspicious or harmful traffic is found. In addition to the improvement in terms of adaptability, this proposed solution is intended to help the intrusion detection system learn from existing patterns of attacks and differentiate these attacks from normal network activity. System performance is measured by traditional performance metrics including accuracy, precision, recall, and F1-score.

---

## 1. Problem Definition

Due to the fast-growing computer networks, cloud computing, and Internet of Things (IoT), the possibilities for cyberattacks and access are increasing. However, attackers are constantly coming up with new methods of conducting cyberattacks that can take advantage of certain flaws in software products, rendering traditional security measures ineffective in detecting such malicious actions. Conventional intrusion detection systems use a set of rules and signatures that can only detect attacks that have already been discovered. The problem is that they might be generating too many false alarms.

As such, the need exists for an Intelligent Intrusion Detection System (IIDS) that can make use of machine learning methods to study network traffic and detect any abnormal behaviour. The IIDS must have the ability to process relevant network characteristics, learn from past traffic records, and classify the network activities into either normal or malicious. Moreover, it will have to identify the type of attack such as DoS, probing, and unauthorized access among others and raise alerts when any form of suspicious activity is observed.

The major issue being addressed by this project is that of developing an efficient and intelligent intrusion detection system which not only helps in the detection of attacks in networks but also minimizes false positives.

---

## 2. Literature Survey

### 2.1 From Traditional IDS to Intelligent IDS
An Intrusion Detection System (IDS) acts like a security guard for a network: it watches traffic. Tries to decide whether an activity is normal or dangerous. Traditional IDS mainly follow two paths. Signature-based systems look for known attack patterns so they are effective against threats but weak against new or rare attacks. Anomaly-based systems learn what normal behaviour looks like, but changing network behaviour can make them produce many false alarms. This limitation has turned research toward Artificial Intelligence (AI), Machine Learning (ML) and Deep Learning (DL). The literature shows that the goal has gradually changed.

Earlier work mainly asked, "Can the system detect an attack?" Modern research asks a harder question: "Can it detect the attack accurately, explain why it happened, protect private data, adapt to new attacks, and still run fast enough in the real world?"

### 2.2 Machine Learning and Deep Learning: Teaching the IDS to Recognise Patterns
ML methods such as Decision Trees, Random Forests, Support Vector Machines and Naïve Bayes are relatively simple and useful for intrusion classification. However network traffic is not simple. It contains numbers of features and complicated relationships. Deep learning models such as CNN, RNN, LSTM, GRU, MLP, DNN and AutoEncoder can learn these patterns automatically reducing the dependence on designed rules.

The reviewed studies show that there is no "best" model for every environment. A CNN can offer a balance between accuracy and computational cost while models such as CNN-BiLSTM may capture more complex patterns but require more resources. Olanrewaju-George and Pranggono also found results from an unsupervised AutoEncoder for IoT intrusion detection. Other work improves the learning process by selecting useful features or optimising model parameters. In one reviewed study feature selection combined with learning achieved 95.59% detection accuracy while another federated deep-learning approach reported 98.24% accuracy and 86.77% F1-score.

### 2.3 Transformers: Looking at the Bigger Picture
CNNs are good at finding patterns and recurrent models are useful for sequences but network traffic can contain relationships that stretch across many features or events. Transformers approach this problem through self-attention: by treating every part of the traffic as equally important, the model can focus on relationships that matter most.

The literature reports Transformer-based IDS approaches. IDS-MTran combines traffic features with Transformer processing and achieved 99.25% binary-classification accuracy on NSL-KDD and 99.16% on its five-class task. MBConv-ViT combines convolution with a Vision Transformer and reported 97.14% accuracy on ToN-IoT and 99.99% on Bot-IoT. However these numbers should not be treated as proof of superiority: Transformer models can be computationally expensive and minority attacks may still be detected poorly when their training data is limited.

### 2.4 The Privacy Problem: Why Centralised Learning Starts to Break
An intelligent IDS usually sends large amounts of network data to a central location for training. This is convenient. It creates a serious trade-off: the more data the system collects, the more sensitive information it may hold in one place. Privacy, communication overhead and the risk of a failure therefore become important concerns, especially in IoT networks.

Federated Learning (FL) changes the old way. Each device trains a model locally, sends model updates rather than raw traffic. A server combines those updates into a shared model, and sends the improved model back. This allows collaboration without pooling all raw data.

### 2.5 Federated Learning: Smarter Collaboration, New Problems
The reviewed studies show that FL can improve privacy while maintaining detection performance. In PEIoT-DS, FedAvgM achieved 95.05% accuracy compared with 94.05% for FedAvg. It also reached 90% accuracy in communication rounds and reduced the false-positive rate from 5.1% to 3.9%. These results show why aggregation strategy matters rather than treating federated learning as a single fixed technique.

FL is not a magic privacy button. Its biggest practical problem is data heterogeneity. Different devices see different traffic, so their local datasets are often non-IID. The Edge-FL study makes this problem very clear: its lightweight 1D-CNN achieved around 99.9% accuracy in cases yet accuracy fell to 52.39% for a difficult 12-class non-IID setting with seven clients. In other words, a model can look almost perfect in a controlled experiment and still stumble when the network becomes messy and uneven.

### 2.6 Lightweight IDS: Putting Intelligence Where the Traffic is
IoT devices do not have CPU power, memory, battery or bandwidth. A huge model may be highly accurate on a computer but impractical on a sensor, vehicle, gateway or industrial device. This is why Edge Computing is increasingly connected with FL. Instead of sending everything to a distant cloud, processing can move closer to where the network traffic is produced.

The literature therefore emphasises architectures, especially compact CNN-based models together with edge processing and federated training. This combination aims to reduce latency and communication while keeping data local. The trade-off must be made: reducing size can significantly affect learning capability, while increasing complexity can increase processing power, energy consumption and delay.

### 2.7 Imbalanced Traffic when Accuracy can be false
Another common problem is class imbalance. A dataset can be dominated by normal traffic and common attacks, while rare attacks have few examples. Thus, a model can report high overall accuracy while silently failing at the attacks that matter most. In the literature, SMOTE is used to generate samples for the minority class. This can improve attack representation, but synthetic data also adds processing requirements and must be handled carefully in privacy-sensitive environments.

### 2.8 Explainability and Robustness
High accuracy alone is not enough for a security system. If an IDS says "attack detected", Explainable AI attempts to open this box. One reviewed approach combines transformer-based learning, SMOTE and CNN-LSTM detection with AI, while HADA-FL uses SHAP to identify the features that contribute most to a decision.

Explainability also connects naturally with robustness. Modern ML-based IDSs can themselves be attacked. Small changes in input traffic may cause a model to classify activity as normal. HADA-FL therefore combines SHAP-guided feature selection with privacy, secure aggregation and testing against attacks such as FGSM, PGD and label-flipping. Its results show that robustness, privacy and explainability are becoming parts of the problem rather than separate research topics.

### 2.9 Adaptability: The Network never stands still
A network is not a static environment. Devices appear and disappear, traffic patterns change, and attackers continuously modify their techniques. A model trained on old traffic can gradually become outdated. Continual learning allows a model to learn new information while attempting to preserve previously learned knowledge.

The aim is to create a system that can learn from new attacks without completely forgetting old ones—a problem known as catastrophic forgetting. The literature suggests that adaptive and federated learning together could make IDS more suitable for changing, distributed networks, although efficient implementation in real-world environments remains an open challenge.

### 2.10 Connected Research Gaps
* **Accuracy versus reality**: Really high benchmark accuracy is not directly synonymous with high real-world performance.
* **Centralization versus privacy**: It is easy to train all data in one place, but not practical to share raw traffic containing sensitive data.
* **FL versus Heterogeneity**: Clients with Non-IID traffic can cause model convergence and performance collapse.
* **Complexity versus deployment**: Sophisticated Transformers or Hybrid architectures require significant GPU memory, energy, and communication bandwidth.
* **Accuracy versus Attacks**: Rare minority threats can go unnoticed in systems showing high overall accuracy due to class imbalance.
* **Detection versus trust**: Explainability must be present so an analyst can trust the reasons behind an IDS alarm.
* **Learning versus change**: Training needs to be incremental as attack patterns and network behavior continuously evolve.

### 2.11 Overall Direction for an IDS
The results suggest that an intelligent IDS must combine Transformer/ML-based feature learning for accurate detection, privacy-preserving techniques (like federated learning), lightweight/edge processing for minimal latency, class-balancing mechanisms (such as SMOTE), explainability via SHAP, and robust defenses against adversarial manipulation.

The key observation remains: **an IDS is no longer represented solely by its model accuracy**. It is a system that remains accurate despite uneven data and shifting adversaries, explains its decisions to an analyst, secures information while learning, and satisfies real-world network constraints.

### 2.12 Conclusion of the Survey
Intelligent intrusion detection is shifting from simple attack detection toward learning-based systems that protect data and adapt to evolving threats. A practical intelligent IDS should achieve a balanced compromise between accuracy, privacy, efficiency, explainability, robustness, and adaptability, rather than focusing on accuracy alone.

---

## 3. Objectives

The main objectives of the Intrusion Detection System are:
1. To develop an efficient Intrusion Detection System which can accurately identify malicious network activities.
2. To have a better detection of diverse cyberattacks like DoS or DDoS, scanning, or brute force.
3. To address imbalance of class in intrusion datasets and improve detection of less frequent attack classes.
4. To make it computationally lightweight and efficient for detection so that processing overhead is reduced.
5. To make detection better for evolving and previously unseen attacks, by methods like anomaly detection.
6. To evaluate IDS using multiple datasets and realistic network traffic.
7. To reduce the chances of false positives and false negatives to increase reliability.
8. To provide security alerts that help users understand why network activity is suspicious.
9. To evaluate the system using standard performance metrics: accuracy, precision, recall, F1-score, and computational efficiency.

---

## 4. Scope

The INIDS project scope is the development of a machine learning system for monitoring network traffic and identifying activities that may represent a cyberattack. The project mainly involves the analysis of network traffic data to extract its features and classify it as benign or malicious.

The main areas addressed by the project are:
* **Network Traffic Monitoring**: The system examines network traffic data to detect anomalies in the network.
* **Data Preprocessing**: Network traffic data is preprocessed, where irrelevant data is removed and features are converted into the appropriate numerical formats.
* **Feature Selection**: Relevant features of the network—including protocol type, duration, packets, and connectivity behavior—are selected in order to detect anomalies effectively.
* **Detection and Classification of Attacks**: The system classifies network traffic and attacks, including Denial-of-Service (DoS), probe/port scans, and unauthorized access attempts.
* **Machine Learning Model**: Supervised and ensemble machine learning algorithms are trained and tested to predict and detect malicious network traffic accurately.
* **Performance Evaluation**: Models are tested using performance metrics such as accuracy, precision, recall, and F1-score.
* **Alert Generation**: The system provides an alert when suspicious or potentially malicious network activity is detected, helping the administrator take further action.
* **Future Scalability**: The system can later be extended to support real-time network traffic monitoring, larger datasets, additional attack categories, and more advanced deep learning techniques.

*Note: This project is geared towards network-level intrusion detection and acts as an intelligent layer of security that works alongside existing defenses like firewalls and anti-virus software.*

---

## 5. Feasibility Study

### 5.1 Technical Feasibility
The proposed IDS can be developed using commonly available programming languages (Python), machine learning libraries (Scikit-learn, Pandas, NumPy), and publicly accessible benchmark datasets (CICIDS2017). It is technically feasible to extract relevant flow features and classify them into normal and malicious traffic with high accuracy and low latency. Utilizing suitable preprocessing and feature-selection techniques alleviates computational complexity.

### 5.2 Operational Feasibility
The proposed system provides an automatic detection mechanism for identifying suspicious network activities along with generating easily understandable security alerts. A user-friendly web interface displaying various types of attacks and real-time security information enables network administrators to quickly identify and respond to security incidents.

### 5.3 Economic Feasibility
The system is built entirely with open-source technologies, programming languages, and publicly available intrusion datasets. There is no requirement for expensive specialized hardware during development or initial deployment. Lightweight, computationally efficient models keep infrastructure and processing requirements low.

### 5.4 Schedule Feasibility
The project follows a planned modular lifecycle:
1. Literature Study & Requirement Analysis
2. Dataset Collection & Preprocessing
3. Feature Selection & Engineering
4. Model Development & Training
5. System Implementation & Dashboard Integration
6. Performance Evaluation & Documentation

All components are developed and tested individually before being integrated into the complete operational system.

---

## References

1. “FL-IIDS: A Novel Federated Learning-Based Incremental Intrusion Detection System,” 2025.
2. N. A. Hamad et al., “Systematic Analysis of Federated Learning Approaches for Intrusion Detection in IoT Environment,” *IEEE Access*, vol. 13, 2025.
3. “Federated Learning in Intrusion Detection: Advancements, Applications, and Future Directions,” *Cluster Computing*, vol. 28, 2025.
4. “Intelligent Deep Federated Learning Model for Enhancing Security in IoT-Enabled Edge Computing,” 2025.
5. T. P. Nguyen, H. Nam, and D. Kim, “Transformer-Based Attention Network for In-Vehicle Intrusion Detection,” *IEEE Access*, vol. 11, pp. 55390–55401, 2023, doi: 10.1109/ACCESS.2023.3282110.
6. M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” in *Proceedings of the IEEE Symposium on Computational Intelligence for Security and Defense Applications*, 2009.
7. N. Moustafa and J. Slay, “UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems,” in *Military Communications and Information Systems Conference (MilCIS)*, 2015.
8. I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” in *International Conference on Information Systems Security and Privacy (ICISSP)*, 2018.
9. A. Khraisat, I. Gondal, P. Vamplew, and J. Kamruzzaman, “Survey of Intrusion Detection Systems: Techniques, Datasets and Challenges,” *Cybersecurity*, vol. 2, no. 20, 2019.
10. M. Ring et al., “A Survey of Network-Based Intrusion Detection Data Sets,” *Computers & Security*, vol. 86, pp. 147–167, 2019.
11. Y. Xin et al., “Machine Learning and Deep Learning Methods for Cybersecurity,” *IEEE Access*, vol. 6, pp. 35365–35381, 2018.
12. W. Wang et al., “HAST-IDS: Learning Hierarchical Spatial-Temporal Features Using Deep Neural Networks to Improve Intrusion Detection,” *IEEE Access*, vol. 6, pp. 1792–1806, 2018.
