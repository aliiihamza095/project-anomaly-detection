<!-- Group 10 | Report 1 | Section file | Owner: Shoaib Haneef -->

**I. INTRODUCTION AND PROBLEM STATEMENT**

A password by itself cannot always protect an account. Someone may steal, phish or guess a user's credentials and then log in with activity that looks much like the real user's. One way to notice this is to examine login habits. Most people tend to sign in around familiar times and use a fairly consistent set of devices and locations. A login late at night from a new device or an unfamiliar place may therefore need a closer look. User and Entity Behavior Analytics (UEBA) refers to approaches that monitor this kind of activity, as described in the course project brief.

Compromised accounts give attackers a way into a system without any technical exploit, and UEBA tries to catch this by comparing present behavior with profiles built from earlier logs [1, Abstract]. Login logs hold personal information, which is why organizations seldom release them and almost no real logs suitable for UEBA are public [1, Abstract; Sec. I]. For that reason, this project uses a synthetic, labeled login dataset of fictional users.

**Problem statement. **The problem addressed is how to detect suspicious logins that use valid credentials by comparing each login with the user’s own normal behavior, while keeping false alarms low and giving a reason for every alert.
