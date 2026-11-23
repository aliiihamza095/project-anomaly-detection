<!-- Group 10 | Report 2 | Section VI parts A-C | Owner: Ali Hamza -->

**VI. ALGORITHM DESIGN**

*A. Normal profiles*

Each user’s profile is built from the training days only. It holds the average login hour and its spread (measured on a 24-hour circle, so 23:00 and 01:00 count as close), the devices the user has used, how often each location category occurs, and the usual round-trip time for each location category. The idea of checking behavior against a profile built from historical logs comes from Landauer et al. [1].

*B. Features*

We compute the eight features in Table V for every login, choosing them from the session characteristics that NIST lists for fraud detection: usage patterns, velocity and timing, device and browser, and geolocation [4].

TABLE V

Features computed for each login

| **Feature** | **Definition** | **Reason for use** |
| --- | --- | --- |
| hour_dev | Distance in hours between the login hour and the user’s average hour. | Timing |
| hour_z | hour_dev divided by the user’s spread of hours. | Timing, scaled for each user |
| new_device | 1 if the device was not seen in the user’s training days. | Device |
| loc_rarity | Minus the logarithm of how often the user logs in from this location category. | Location |
| failed_attempts | Failed tries in the sequence (from the data). | Failures |
| rtt_z | Round-trip time compared with the usual value for its location category. | Network |
| fails_10m | Number of the user’s failed logins in the last 10 minutes. | Velocity |
| logins_60m | Number of the user’s logins in the last 60 minutes. | Velocity |

*C. Statistical detector*

The statistical detector relies on z-scores and fixed rule thresholds, which are among the oldest techniques for finding anomalies [5]. A login is flagged if any one of four rules fires: its hour is more than three standard deviations from the user’s average; the device is new; the location category made up fewer than 0.5% of the user’s training logins; or five or more failures occurred within 10 minutes. The alert level depends on how many rules fire (one is Low, two is Medium, three or more is High), and the reasons given for an alert are simply the rules that fired.
