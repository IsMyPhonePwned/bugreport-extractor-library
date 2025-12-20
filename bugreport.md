# Android Bug Report Acquisition Guide (No USB Debugging)

This guide details how to capture system logs and bug reports on Android devices without using a computer (ADB) or enabling USB Debugging. Most methods rely on manufacturer-specific "Secret Codes" or engineering menus.

---

## 1. Samsung Galaxy Devices (SysDump)
**Works for:** S-Series, Z-Flip, Z-Fold, A-Series (One UI)
**Requires Developer Mode:** NO

1.  Open the **Samsung Phone** app (do not use Google Phone or third-party dialers).
2.  Dial `*#9900#`.
3.  A menu titled **SysDump** will appear.
4.  Tap **Run dumpstate/logcat/modem log**.
5.  Wait for the process to finish (usually silent or shows a loading spinner).
6.  **Crucial Step:** Scroll down and tap **Copy to sdcard (include CP Ramdump)**.
7.  **File Location:** * Open **My Files** > **Internal Storage** > **log**.
    * Look for a file named `dumpState_<model>_<date>.zip`.

### ⚠️ Troubleshooting: Samsung Z Flip 7 (One UI 6/7)
If dialing `*#9900#` does nothing on your newer Samsung device:

* **Issue 1: Auto Blocker is On (Most Likely)**
    1.  Go to **Settings** > **Security and Privacy**.
    2.  Tap **Auto Blocker**.
    3.  **Turn OFF** Auto Blocker temporarily.
    4.  Retry the code.
* **Issue 2: Carrier Restrictions (Verizon/AT&T)**
    * US Carriers often disable these codes. 
    * **Workaround:** Open the **Samsung Members** app > **Support** > **Error Reports**. Send a report and email the resulting log file to yourself.

---

## 2. Xiaomi / Redmi / POCO (MIUI & HyperOS)
**Works for:** Most Xiaomi ecosystem devices
**Requires Developer Mode:** NO

1.  Open the **Dialer/Phone** app.
2.  Dial `*#*#284#*#*`.
3.  The phone will vibrate immediately and show a notification: "Generating bug report...".
4.  Wait for the notification to say "Created".
5.  **File Location:**
    * **File Manager** > **Internal Storage** > **MIUI** > **debug_log**.
    * The file is a `.zip` archive.

---

## 3. OnePlus / OPPO / Realme (LogKit)
**Works for:** ColorOS, OxygenOS, RealmeUI
**Requires Developer Mode:** NO

1.  Open the **Dialer/Phone** app.
2.  Dial `*#800#`.
3.  This opens the **Feedback** or **LogKit** app.
4.  Select a category (e.g., "System" or "Other").
5.  Tap **Start Logging**.
6.  Reproduce your bug/crash.
7.  Return to the app and tap **Stop Logging**.
8.  **File Location:**
    * **File Manager** > **Phone Storage** > **Android** > **data** > **com.oplus.logkit** > **files** > **Log**.
    * *(Note: On Android 11+, you may need a third-party file manager like "Solid Explorer" to view the Android/data folder).*

---

## 4. Huawei / Honor (Project Menu)
**Works for:** EMUI, MagicOS
**Requires Developer Mode:** NO

1.  Open the **Dialer/Phone** app.
2.  Dial `*#*#2846579#*#*`.
3.  Go to **Background Settings** > **Log Settings**.
4.  Check the logs you need (AP Log, Charge Log, etc.) and tap **Log switch**.
5.  Reproduce the issue, then turn logging off.
6.  **File Location:**
    * **Files** > **Internal Storage** > **log** (or **ProjectMenu** folder).

---

## 5. Google Pixel / Motorola / Sony (Stock Android)
**Works for:** "Clean" Android versions
**Requires Developer Mode:** YES (Mandatory)

These devices *do not* have secret codes to dump logs to storage. You must use the Developer Options menu.

1.  Go to **Settings** > **About Phone**.
2.  Tap **Build Number** 7 times to enable Developer Mode.
3.  Go to **Settings** > **System** > **Developer Options**.
4.  Tap **Take bug report** > **Interactive report**.
5.  Wait for the notification "Bug report captured" (2-5 mins).
6.  **File Retrieval:**
    * You **cannot** browse to the file manually due to permissions.
    * You must tap the **Notification** when finished and share it to **Google Drive** or **Email**.

---

## Summary Cheat Sheet

| Brand | Secret Code | Action Required | Location (Internal Storage) |
| :--- | :--- | :--- | :--- |
| **Samsung** | `*#9900#` | Select "Copy to sdcard" | `/log` |
| **Xiaomi / POCO** | `*#*#284#*#*` | Auto-generates | `/MIUI/debug_log` |
| **OnePlus / OPPO** | `*#800#` | Use LogKit UI | `/Android/data/com.oplus.logkit` |
| **Huawei** | `*#*#2846579#*#*` | Project Menu UI | `/log` |
| **Pixel / Moto** | N/A | Dev Options Menu | Via Notification Share |