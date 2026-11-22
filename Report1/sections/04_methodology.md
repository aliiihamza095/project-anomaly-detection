<!-- Group 10 | Report 1 | Section file | Owner: Tabraiz Khan -->

**IV. METHODOLOGY AND TOOLS**

**A. Synthetic dataset design**

The group will generate its own dataset with a Python script and a fixed random seed. It covers fictional users, each given one of four normal patterns, and uses only documentation-range IP addresses. A record holds a user ID, timestamp, device ID and type, operating system, browser, location category, IP address, round-trip time, login result and number of failed attempts, plus labels that are used only for evaluation and never shown to the detectors. Attack injection and labeling follow Komadina et al. [3, pp. 9–11] and Landauer et al. [4, p. 408]. Table I lists the planned user types, and Table II lists the events that will be injected.

TABLE I

Planned user types

| **User type** | **Users** | **Normal pattern** |
| --- | --- | --- |
| Day shift | 25 | Weekday logins, mostly between 08:00 and 17:30, mainly from campus, one or two devices. |
| Evening | 15 | Logins between about 16:00 and 23:30, mainly from the home city. |
| Night shift | 10 | Logins between about 22:00 and 06:00, from the home city. |
| Remote or mixed | 10 | Irregular hours between 07:00 and 23:00, from the home city and another city, two or three devices. |

TABLE II

Events injected into the dataset

| **Event** | **Description** | **Label** |
| --- | --- | --- |
| Unusual hour | A login at an hour that is unusual for the user, either clearly or only slightly outside the normal hours. | Anomaly |
| New device | A login from a device never seen for that user. | Anomaly |
| Location change | A login from an unusual location category, such as another city, a VPN or an unknown or foreign location. | Anomaly |
| Combined event | An unusual hour together with a new device and an unknown or foreign location. | Anomaly |
| Failed-login burst | Many failed attempts within minutes, sometimes ending in a successful login (possible takeover). | Anomaly |
| Travel, new phone, late session | Harmless unusual events, such as a user travelling, buying a new phone or working late once. | Normal |

Anomalies will make up a few percent of the records. 

**B. Features and normal profiles**

Planned features are the hour and day of a login, whether the device is new to the user, the location category and how unusual it is for that user, login counts over a period, failed attempts within a short window, and round-trip time. A user’s profile will record their usual login times, familiar devices, average daily logins, typical locations and failure rate.

**C. Detection methods**

Two detectors will be compared. The statistical one will test each login against the user’s profile with z-scores, the interquartile range or fixed rules, a family of methods that is among the oldest in anomaly detection [7, p. 78659]. The machine learning one will be Isolation Forest [5], fitted for each user in the profile-comparison style of [1], with categorical fields encoded as numbers. Komadina et al. found it the best of 13 unsupervised models on logs with injected attacks, although its scores were low [3, pp. 16–17]. Both detectors will be compared by anomaly type.

**D. Evaluation**

Anomalies are rare, and accuracy alone is a weak yardstick [7, p. 78690], so the evaluation will use precision, recall, F1-score, a confusion matrix and a false-positive analysis, including how each method treats the harmless unusual events. Thresholds will be tuned to balance false alarms against missed attacks. The share of false positives among all records will be reported as a rough gauge of analyst workload [3, p. 17], and the area under the precision-recall curve will be considered because it suits imbalanced data [3, p. 14].

**E. Explanation, risk levels and response plan**

Each flagged login will list why it was flagged, for example an odd hour together with an unrecognized device, and will receive a risk score that maps to a Low, Medium or High alert level. A response plan will assign an action to each level, such as requesting a second factor, locking the account temporarily, sending a notification or opening an investigation, and a short access-control policy will summarize these actions. The design is consistent with NIST’s guidance on reauthentication, session termination or notifying support staff [2, Sec. 5.3, p. 57].

**F. Tools**

TABLE III

Tools and their purpose

| **Tool** | **Purpose** |
| --- | --- |
| Python 3 with pandas, NumPy and SciPy | Data generation, profiling and statistical methods. |
| scikit-learn | Isolation Forest and evaluation metrics. |
| Matplotlib and Seaborn | Distribution, pattern and anomaly-score charts. |
| VS Code (Google Colab as a fallback) | Development environment. |
| Git and a private GitHub repository | Version control with regular commits and the instructor added as a collaborator. |
| requirements.txt, README and fixed seed | Reproducibility of all results. |

**G. Ethics and scope**

Only synthetic data is used: the users are fictional, the IP addresses come from documentation ranges, and no real logs, accounts or systems are used or tested. Behavioral monitoring raises privacy and fairness questions, which NIST also notes for session characteristics [2, Sec. 5.3, p. 57], so the final report will discuss them.
