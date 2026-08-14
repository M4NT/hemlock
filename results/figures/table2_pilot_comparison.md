**Table 2.** Bypass rate per category per defense type (ingest-guard metric).

| Attack category              |    Composite | full_proposed |        Regex |     Semantic |
|------------------------------|--------------|--------------|--------------|--------------|
| citation_forgery             |           0% |           0% |         100% |           0% |
| cross_tenant_poisoning       |           0% |           0% |         100% |           0% |
| jailbreak_via_context        |           0% |           0% |          83% |           0% |
| semantic_backdoor            |         100% |           0% |         100% |         100% |
| temporal_spoofing            |           0% |           0% |         100% |           0% |
| **OVERALL**                  |          20% |           0% |          97% |          20% |