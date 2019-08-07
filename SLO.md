While the application the support and up time will be best effort. To put some more context around best effort, we are looking to loosely provide the following level of service:

- Support: Community based. Using a shared slack room and issues opened up in a repository.
- Service availability support: US Eastern business hours. If it breaks after those hours it will be look at the start of the next business day
- Service schedule maintenance: The solution is designed with zero schedule outages for maintenance
- Backup: The application does not store any data. All the data is stored in GitHub, and will be subject to their SLO
- Scan Queued target: We target the scan to be started within a minute
- Scan run length: This is dependent on the code size, but for small repos we target this for 30 seconds upper limit
- Security: we will keep everything patched, based on known security vulnerabilities. We look at patching everything the same day when the patch is available.
- False positives: we are looking to keep this some where around 50%. This include items, which are testing secrets (secrets which are meant to mimic production secrets ).
