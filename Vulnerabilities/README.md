To make this analyzer work you need your vulnerability data in the following format, somewhat following Elastic Common Schema (ECS) version 1.5. 
The format is made by looking at fields in a .nessus XML file, but can be used for all vulnerability data in an Elasticsearch 6.8 database.

| .nessus-file Fields      | Data                                                                                                               | ECS1.5 Fields + custom                             |
|--------------------------|--------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| Credentialed_Scan        | false                                                                                                              | [vulnerability][custom][credentialed_scan]         |
| cve                      | CVE-2009-2412                                                                                                      | [vulnerability][id]                                |
| cvss_base_score          | 10                                                                                                                 | [vulnerability][score][base]                       |
| cvss_vector              | CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C                                                                                   | [vulnerability][custom][vector]                    |
| description              | According to its self-reported banner, the version of Apache 2.2.x running on the remote host is prior to 2.2.13.  | [vulnerability][description]                       |
| end_time                 | Jan 6, 2020 @ 21:33:26.000                                                                                         | [vulnerability][custom][plugin][end_time]          |
| exploit_available        | FALSK                                                                                                              | [vulnerability][custom][exploit_available]         |
| file_processed           | 2020_01_06-14.nessus                                                                                               | [vulnerability][custom][file_processed]            |
| fqdn                     | testdevice.company.local                                                                                           | [host][custom][fqdn]                               |
| host_ip                  | 192.168.5.10                                                                                                       | [host][ip]                                         |
| host_name                | testdevice.company.local                                                                                           | [host][name]                                       |
| in_the_news              | -                                                                                                                  | [vulnerability][news]                              |
| os                       | windows                                                                                                            | [host][os][family]                                 |
| plugin_family            | Web Servers                                                                                                        | [vulnerability][category]                          |
| plugin_id                | 57603                                                                                                              | [vulnerability][custom][plugin][id]                |
| plugin_modification_date | Jan 18, 2012 @ 18:00:00.000                                                                                        | [vulnerability][custom][plugin][modification_date] |
| plugin_name              | Apache 2.2.x < 2.2.13 APR apr_palloc Heap Overflow                                                                 | [vulnerability][custom][plugin][name]              |
| plugin_output            | Version source : Server: Apache/2.2.10 (Win32) mod_fastcgi/2.4.6 Installed version : 2.2.10 Fixed version : 2.2.13 | [vulnerability][custom][plugin][output]            |
| plugin_publication_date  | Jan 18, 2012 @ 18:00:00.000                                                                                        | [vulnerability][custom][plugin][publication_date]  |
| plugn_type               | remote                                                                                                             | [vulnerability][custom][plugin][type]              |
| port                     | 80                                                                                                                 | [source][port]                                     |
| protocol                 | tcp                                                                                                                | [network][transport]                               |
| report_name              | 1st Quarter - Part 1 - 192.168.5.1/20                                                                              | [vulnerability][custom][report_name]               |
| risk_factor              | Critical                                                                                                           | [vulnerability][severity]                          |
| scan_duration            | 8                                                                                                                  | [vulnerability][custom][scan_duration]             |
| see_also                 | http://httpd.apache.org/security/vulnerabilities_22.html                                                           | [vulnerability][reference]                         |
| severity                 | 4                                                                                                                  | [vulnerability][custom][severity]                  |
| solution                 | Upgrade to Apache 2.2.13 or later.                                                                                 | [vulnerability][custom][solution]                  |
| start_time               | Jan 6, 2020 @ 21:25:51.000                                                                                         | [vulnerability][custom][plugin][start_time]        |
| svc_name                 | www                                                                                                                | [vulnerability][custom][service]                   |
| synopsis                 | The remote web server is affected by a buffer overflow vulnerability.                                              | [vulnerability][custom][synopsis]                  |


Screenshot of the long report is here: [Vulnerability Analyzer screenshot](https://github.com/LaZyDK/TheHive-Cortex-Analyzers/blob/master/Vulnerabilities/Screenshots/VulnerabilityAnalyzerPreview.jpg)
