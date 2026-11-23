<!-- Group 10 | Report 1 | Section file | Owner: Ali Hamza -->

**II. OBJECTIVES**

This project aims to develop a login-behavior anomaly detector that can explain why it flags an event. Using a synthetic dataset, the group will compare a statistical approach with a machine-learning approach and examine which types of unusual logins each method detects, along with the false alarms each one produces.

	**O1.**	Examine how credential stuffing (reusing a password stolen from another site, also called password stuffing [2, Sec. 8.1.2.1, p. 72]), brute force and account takeover show up in login logs, and choose the signals that separate them from normal use: time, device, location category, failed attempts and login frequency. The starting point is the list of session characteristics that NIST gives for fraud detection [2, Sec. 5.3, p. 57].

	**O2.**	Design and generate a reproducible synthetic login dataset of at least 10,000 records for at least 50 fictional users, each with a distinct normal pattern, with documented and labeled injected anomalies, harmless unusual events, a data dictionary and a fixed random seed. The injection of labeled attack records into normal ones draws on Komadina et al. [3, pp. 9–11], while the random timing and labeling of simulated attacks draws on Landauer et al. [4, p. 408].

	**O3.**	Build a normal profile for each user (usual hours, devices, average daily logins, location categories and failure rate) and derive features from it, in the spirit of comparing each user with a profile built from past logs [1, Abstract].

	**O4.**	Detect anomalies with two detectors, a statistical one (z-scores, interquartile range or fixed rule thresholds) and a machine learning one, Isolation Forest [5, pp. 1479, 1481], and compare them on each anomaly type using precision, recall and F1-score, including how each one handles harmless unusual events.

	**O5.**	Give every flagged login its reasons and a Low, Medium or High risk level (a design decision of the group), tune the thresholds, and attach an action to each level (a second factor, a temporary lock or a notice to the security team), written up as a brief access-control policy. This mirrors NIST’s advice to reauthenticate, end the session or alert support staff when fraud is suspected [2, Sec. 5.3, p. 57].
