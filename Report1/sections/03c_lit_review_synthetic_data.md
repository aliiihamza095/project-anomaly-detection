<!-- Group 10 | Report 1 | Section III Literature review | Owner: Tabraiz Khan (sources: Landauer testbed; research gap) -->

**III. LITERATURE REVIEW**

This section reviews the seven sources the group has studied so far. It is organized by topic and ends with the gap that this project addresses.

**D. Synthetic data for evaluating detectors**

Landauer et al. [4] take a simulation route instead, using model-driven engineering to keep the infrastructure, the normal behavior and the attack scenarios as separate modules [4, p. 402]. Simulated users pick actions by probability, go idle at random and stay inactive at night to mimic daily routines [4, p. 408]. Attacks such as brute-force logins happen at random times and are labeled from the logged attack steps [4, pp. 408–409]. The limits they report are real-time data generation and imprecise labels when normal and malicious events resemble each other [4, pp. 409, 413–414]. A related caution comes from Landauer et al. [1, Table I]: synthetic data may produce unrealistically low false alarm rates.

**E. Research gap and contribution**

Taken together, the sources support several points. UEBA depends on per-user profiles [1]. Real behavior is unstable and real logs are rarely published [1]. Isolation Forest is a common unsupervised choice, but its scores have known artifacts [5]. Unsupervised methods struggle when anomalies are disguised [3, p. 23]. The web-server study lacked labels to measure its errors [6, pp. 6, 21], and NIST offers response guidance but no detector [2, Sec. 5.3, p. 57]. This project addresses that gap with a synthetic dataset in which every user has a distinct normal pattern, with labeled anomalies of several types alongside harmless unusual events, and with precision, recall, F1-score and false positives reported for each anomaly type. Each alert is explained and mapped to a response level, following NIST’s session-monitoring guidance [2, Sec. 5.3, p. 57]. Because the data are synthetic, false alarm rates may look better than they would on real data [1, Table I].
