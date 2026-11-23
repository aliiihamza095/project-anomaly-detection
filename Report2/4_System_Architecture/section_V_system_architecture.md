<!-- Group 10 | Report 2 | Section V | Owner: Ali Hamza -->

**V. SYSTEM ARCHITECTURE**

Fig. 6 shows the planned pipeline. The generator writes the login records and their hidden labels. A preprocessing step splits the records by time. Profiles are built from the training days, and features are extracted for every login. Two detectors score each login, the statistical detector and the Isolation Forest. Their output becomes a risk level with reasons, which is linked to a response. The labels enter only in the evaluation step.

Fig. 6. Planned architecture of the login anomaly detection system.

Each box will be a separate Python module in the project repository, so that the group members can work on different parts and test them separately. The implementation uses Python with pandas, NumPy, SciPy, scikit-learn and Matplotlib, and the code is kept in a private GitHub repository with a README and a requirements file.
