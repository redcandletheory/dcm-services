# Shipped System Objects vs. Internal IBM Development Headers

| Include / Object | Status on Customer Systems | Location / Access Command |
| :--- | :--- | :--- |
| **`/QIBM/include/gskssl.h`** | Shipped (5770-SS1 Option 13) | `DSPF STMF('/QIBM/include/gskssl.h')` |
| **`QSYSINC/H(GSKSSL)`** | Shipped (5770-SS1 Option 13) | `DSPPFM FILE(QSYSINC/H) MBR(GSKSSL)` |
| **`QSYSINC/H(QSYCDCM)`** | Shipped (5770-SS1 Option 13) | `DSPPFM FILE(QSYSINC/H) MBR(QSYCDCM)` |
| **`QSYS/QFLAGSK`** | Shipped (OS Base Service Program) | `DSPOBJD OBJ(QSYS/QFLAGSK) OBJTYPE(*SRVPGM)` |
| **`gskkmerr.h`** | Internal IBM header, not shipped | Not on the system. The page's reference data (`unified_dcm_db.json`) carries its codes. |
| **`qycuretcodes.H`** | Internal IBM header, not shipped | Not on the system. The page's reference data (`unified_dcm_db.json`) carries its codes. |
