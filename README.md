# IBM i WRKPRB, IAS Log and GSKit

### Target Runtime: **Integrated Application Server (IAS) / WebSphere Liberty Profile on IBM i (V7R3, V7R4, V7R5, V7R6)**
* **Works with any IAS instance**: the page analyzes the admin or application server logs of **any** IAS instance running secured (TLS) jobs, not only the `ADMIN3` instance. Paste the log from whichever instance you are troubleshooting.
* **Context Root**: `/dcm-service`
* **Artifact Package**: `dcm-service.war`
* **Shipped objects vs. internal IBM headers**: See [`ARCHITECTURE_AND_DIAGNOSTICS.md`](ARCHITECTURE_AND_DIAGNOSTICS.md)
* **Detailed Technical Guide**: See [`USER_GUIDE.md`](USER_GUIDE.md)

---

## 🏗️ Architecture & Features

This application delivers a self-contained, browser-based diagnostic analyzer and REST API for IBM i administrators, systems programmers, and support teams:

The page has four tabs:

1. **Symptom String / WRKPRB**: splits a WRKPRB symptom string (`5770 SP/… MOD/… RC…`) into major entry point + utility function + local failure point, using the DCM reference tables.

2. **IAS Admin Log (TLS)**: parses the log of any IAS instance that runs secured (TLS) jobs (`SystemOut`, `SystemErr`, `messages`).
   - The decoded log (the black box) is the main result and appears directly under the pasted log. `rc:` values are hoverable, and EBCDIC hex is decoded in place.
   - Below it, **API Errors Found in the Log** shows one green explanation box per distinct API call: the `function: … / rc: …` call matched to the DCM entry-point table, the return code and the header it is defined in, and the keystore path decoded from the log. Identical repeated calls are merged and counted. `GSKit Error is …` / `gsk error …` lines get their own box.
   - Every `ProgramParameter` is decoded (EBCDIC Code Page 037 text, or a 4-byte integer output), so paths such as `/QIBM/UserData/ICSS/Cert/Server/DEFAULT.KDB` come from the log itself.
   - **Lock button** (right side): locks the pasted log and the decoded log together. Hex decoding changes the text of a line, and so how it wraps, but never the number of lines, so line N is the same line in both logs. Scroll either one and the other follows to the same log line. The status line shows the line number and how many characters the line (and the whole log) changed from pasted hex to decoded text. `rc:` lines are marked, and clicking a line highlights it in both logs. While locked, the other controls are hidden so the two logs get the room. Unlock to run another search.

3. **GSKit / API Return Codes**: looks up GSKit key management (`gskkmerr.h`), SSL/TLS (`gskssl.h`, e.g., `GSK_ERROR_IO` = 406, `GSK_AS400_ERROR_NOT_TRUSTED` = 6000, `GSK_AS400_ERROR_NO_DEFAULT_CERT` = 6019) and QYCU (`qycuretcodes.H`) return codes, with the constant name and the header it comes from.

4. **Complete Matrix Directory**: a universal search over every code in one table. It tries successively looser methods until something is found and always shows the closest candidates when there is no exact match:
   1. a reason code split into entry point + utility function + local failure point (full or partial WRKPRB string, or a bare `RC7027500`, with misspelled program names corrected);
   2. exact text;
   3. a number or hex value (`0x19F`, `FFFFFFFA`);
   4. a partial IAS log (`function:`, `rc:`, `GSKit Error is`);
   5. a regular expression;
   6. a scored fuzzy ranking (name words, spelling distance, shared digits, numeric closeness).

   A note above the table says which method matched and how confident it is.

Results are built from the reference data and the pasted log; the page does not carry per-code explanations. If pasted text belongs to a different tab, an orange warning offers to switch.

---

## 🏛️ Verified Source Locations on IBM i

| Object / Member | Physical Location on IBM i | Licensed Program | Purpose |
| :--- | :--- | :--- | :--- |
| **`QSYSINC/H(GSKSSL)`**<br>`/QIBM/include/gskssl.h` | `DSPF STMF('/QIBM/include/gskssl.h')`<br>`WRKMBRPDM FILE(QSYSINC/H) MBR(GSKSSL)` | **5770-SS1 Option 13** (*System Openness Includes*) | Defines official TLS/SSL protocol return codes (`0` to `501`) and IBM i extended return codes (`6000` to `6021`). |
| **`QSYS/QFLAGSK`** | `DSPOBJD OBJ(QSYS/QFLAGSK) OBJTYPE(*SRVPGM)` | **5770-SS1 Base** | IBM i runtime service program providing GSKit SSL/TLS cryptographic routines. |
| **`DEFAULT.KDB`** | `/QIBM/UserData/ICSS/Cert/Server/DEFAULT.KDB` | **5770-SS1 Option 34** (*Digital Certificate Manager*) | Default IBM i system certificate key database. |
| **`DEFAULT.STH`** | `/QIBM/UserData/ICSS/Cert/Server/DEFAULT.STH` | **5770-SS1 Option 34** (*Digital Certificate Manager*) | Encrypted password stash file for system certificate store. |
| **`SystemOut` / `messages` logs** | the `logs/` folder under your instance's `server.config.dir` (the IAS log header prints it, for example `/QIBM/UserData/OS/AdminInst/<instance>/wlp/usr/servers/<server>/`) | **5770-DG1** (*HTTP Server for i*) / IAS | Liberty trace log of the IAS instance. Paste lines from any IAS instance running secured (TLS) jobs. |

---

## 🔨 How to Build the WAR File (Maven)

### Why Maven

The WAR is a standard Java web application, and Maven builds it the same way on every machine from one file, [`pom.xml`](pom.xml):

- **Dependencies are declared, not copied.** `pom.xml` lists Jackson (JSON for the REST API) and `jt400` (IBM Toolbox for Java). Maven downloads them and packs them into `WEB-INF/lib` of the WAR. The Java EE APIs (`javax.servlet`, `javax.ws.rs`) are marked `provided`, because the IAS / Liberty runtime already supplies them. They are used to compile but are not packed into the WAR.
- **One command does everything:** compile the Java 8 sources, run the unit tests, and assemble the WAR with the page (`index.html`), the reference data (`unified_dcm_db.json`), `web.xml` and the libraries.
- **The output name is fixed.** `<finalName>dcm-service</finalName>` in `pom.xml` always produces `dcm-service.war`. That name is the context root (`/dcm-service`) and the service name in IAS, so do not rename it.
- **Tests run on every build.** `DcmSearchServiceTest` checks the symptom-string decoding against the reference data, so a bad change fails the build instead of reaching the server.

You build on a workstation (Windows, Linux or macOS), not on IBM i. Only the finished `dcm-service.war` is copied to IBM i.

### What you need

| Tool | Version used here | Notes |
| :--- | :--- | :--- |
| JDK | 8 (1.8.0_471) | `pom.xml` compiles for Java 8 (`maven.compiler.source/target` = 1.8). Built and tested with JDK 8. |
| Apache Maven | 3.9.6 | Built and tested with 3.9.6. |
| Network access to Maven Central | first build only | Maven downloads the dependencies once into your local repository (`~/.m2/repository`). |

### Install Maven

1. Install a JDK and make sure `JAVA_HOME` points to it.
2. Download the binary zip/tar.gz from <https://maven.apache.org/download.cgi> and unpack it, for example to `C:\ProgramData\apache-maven\apache-maven-3.9.6` (Windows) or `/opt/apache-maven-3.9.6` (Linux/macOS).
3. Add the `bin` folder of that directory to your `PATH`.
4. Open a **new** terminal and check both tools:
   ```powershell
   java -version
   mvn -v
   ```
   `mvn -v` prints the Maven version, the JDK it found, and the Maven home. If it says the command is not found, the `PATH` change did not take effect in that terminal. If it shows the wrong JDK, fix `JAVA_HOME`.

### Build

From the project root (the folder that contains `pom.xml`):
```powershell
mvn clean package
```
Maven downloads the dependencies (first build only), compiles, runs the 8 unit tests, and writes:
```
target/dcm-service.war
```
A successful build ends with `BUILD SUCCESS`. Copy that file to IBM i as described in the deploy section below.

### Build offline or without Maven Central

After one successful online build, every dependency is in `~/.m2/repository`, and you can build without a network:
```powershell
mvn -o package
```
For a machine that never has internet access, run one online build on another machine and copy its `~/.m2/repository` folder over, or point Maven at your company's repository mirror in `~/.m2/settings.xml`.

### Troubleshooting

| Symptom | Cause and fix |
| :--- | :--- |
| `mvn` is not recognized | `bin` of Maven is not on the `PATH`, or the terminal was opened before the change. Open a new terminal. |
| `The JAVA_HOME environment variable is not defined correctly` | Point `JAVA_HOME` at the JDK folder (not at `bin`). |
| `invalid target release` or `release version not supported` | The JDK is older than 8. Use JDK 8 or later. |
| `Could not transfer artifact …` or `Connection refused` | No route to Maven Central. Use a proxy in `settings.xml`, a repository mirror, or `mvn -o package` if the dependencies are already downloaded. |
| `Tests run: … FAILURE` | A unit test failed. Read the line after `FAIL` in the output: the symptom decode no longer matches `unified_dcm_db.json`. Fix the cause. Do not skip the tests to get a WAR. |
| `mvn clean` fails on a file under `target/` | A leftover Java or Explorer process holds the file. Run `mvn package` without `clean`, or copy `pom.xml` and `src/` into a temp folder and build there. |
| The WAR does not start in IAS | Check the IAS log for the first error. The WAR needs the Servlet 3.1 / JAX-RS 2.1 APIs that Liberty provides. Do not add `javax.servlet` or `javax.ws.rs` jars to `WEB-INF/lib`. |

Keep the file name `dcm-service.war` so the context root `/dcm-service` and the service name in IAS stay the same.

### What is inside the WAR

| Path | Content |
| :--- | :--- |
| `index.html` | the four-tab page. It runs entirely in the browser and does not call the server. |
| `WEB-INF/classes/unified_dcm_db.json` | the reference data (programs, entry points, utility functions, GSKKM/GSKSSL/QYCU codes) |
| `WEB-INF/classes/com/ibmi/ias/…` | the optional REST/servlet API (below) |
| `WEB-INF/lib/` | Jackson and `jt400` |

### Optional REST API

The same decoding is available over HTTP under `/dcm-service/api` for scripts and monitoring:

| Method and path | Purpose |
| :--- | :--- |
| `GET /dcm-service/api/status` | health check (status, OS and Java version) |
| `GET /dcm-service/api/dcm/decode?symptom=…` | decode one symptom string, for example `5770 SP/QYCULCAMGR MOD/QYCULCAMGR RC7027500` |
| `POST /dcm-service/api/dcm/search` | decode several symptom strings, one per line in the request body |
| `POST /dcm-service/api/program/call?lib=MYLIB&pgm=MYPGM&outLen=100` | call an IBM i program through JT400 (not used by the page) |



---

## Rules for examples (placeholders and presets)

- Every example must belong to the tab it appears on. Tab 1 shows symptom strings, tab 2 shows IAS admin log API-call traces, tab 3 shows bare return codes, and tab 4 shows search terms.
- At most 3 examples per tab, counting placeholder lines and preset buttons.
- Never use real log data. No real user profiles, host names, job numbers, timestamps or personal paths (for example `/home/<person>`). Generic IBM i names such as `QSECOFR`, `/QIBM/UserData/...` and `/QIBM/UserData/OS/AdminInst/...` are fine.

---

## 🚀 How to Deploy on IBM i (IAS / Liberty)

### Method 1: Dropin Directory (Fastest)
1. Transfer `dcm-service.war` to `/tmp/dcm-service.war` on IBM i via binary FTP/SFTP.
2. Copy the file into the server instance dropin folder:
   ```cl
   CPY OBJ('/tmp/dcm-service.war') +
       TODIR('/www/<instance>/wlp/usr/servers/<instance>/dropins') +
       REPLACE(*YES)
   ```
3. Open `http://<YOUR_IBMI_HOST>:<PORT>/dcm-service/` in your browser.

### Method 2: IBM Web Administration for i GUI (`HTTPAdmin`)
1. Open `http://<YOUR_IBMI_HOST>:2001/HTTPAdmin`.
2. Under **Manage** &rarr; **Application Servers**, select your server instance.
3. Click **Install New Application**, select `dcm-service.war`, set context root to `/dcm-service`, and complete the wizard.
