<!-- Group 10 | Report 2 | Section VI parts D-F | Owner: Shoaib Haneef -->

**VI. ALGORITHM DESIGN (parts D to F)**

*D. Isolation Forest*

Isolation Forest finds anomalies by isolating them instead of modeling normal data, on the assumption that anomalies are few and different [6]. We fit one model on the training records with the eight features above, using 100 trees and a sub-sample of 256 records per tree, which are also the scikit-learn defaults. A login is flagged when its anomaly score is above the 96th percentile of the training scores, so roughly four in a hundred logins are flagged. The method needs no labels, and it has been applied to user-activity data before [7]. Extended Isolation Forest corrects a bias of the standard version [6], and we mention it as a possible improvement.

*E. Risk levels, reasons and response*

For the Isolation Forest, the alert level will depend on the score, with higher quantiles giving Medium and High, and the reasons will be the features that pass their thresholds, such as an unusual hour or a new device. Each level will map to an action consistent with NIST, which suggests reauthentication, ending the session or notifying support staff when fraud is suspected [4]. Low will be logged for review, Medium will request an extra authentication step, and High will end the session or lock the account for a while and alert the security team. The full access-control policy will be written for the final report.

*F. Evaluation plan*

Results will be reported with precision, recall, F1-score and a confusion matrix, since accuracy alone cannot judge a model well [5]. We will also give the percentage of false positives, the recall for each anomaly type, and the number of harmless events that get flagged. Labels are used only for this scoring [2].
