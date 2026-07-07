import json
from db_manager import save_pentest_tools_result

domain = "potensibatik-jateng.ce.undip.ac.id"
report_path = "reports/pentest_tools_potensibatik-jateng_ce_undip_ac_id.json"

with open(report_path, "r", encoding="utf-8") as f:
    report_json = json.load(f)

print(f"Re-parsing report for {domain}...")
save_pentest_tools_result(domain, report_json)

domain2 = "www.lib.pdsmk.fk.undip.ac.id"
report_path2 = "reports/pentest_tools_www_lib_pdsmk_fk_undip_ac_id.json"
try:
    with open(report_path2, "r", encoding="utf-8") as f:
        report_json2 = json.load(f)
    print(f"Re-parsing report for {domain2}...")
    save_pentest_tools_result(domain2, report_json2)
except Exception as e:
    pass
