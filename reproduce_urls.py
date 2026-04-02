
from regex_extractor import RegexExtractor

urls = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "http://www.server.com/%2e%2e/%2e%2e",
    "http://www.example.com///file/",
    "https://rockwellautomation.custhelp.com/app/answers/detail/a_id/537599",
    "http://php.net/security-note.php",
    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900",
    "http://svn.example.com",
    "http://openwall.com/lists/oss-security/2013/12/04/6",
    "http://user:pass@server:port/",
    "http://en.wikipedia.org.evilsite.example/",
    "http://gpu",
    "http://:80",
    "https://jinja.palletsprojects.com/en/master/faq/#why-is-autoescaping-not-the-default",
    "http://example.com?--",
    "http://www.%humbug-URL%.local/bluecoat-splash-API?%BASE64-URL%",
    "http://rebootv5.adsunflower.com/ps/fetch.do",
    "http://fm.grandstream.com/gs/",
    "http://mysite.example.com",
    "http://should-have-been-filtered.example.com/?http://google.com",
    "http://javascript:payload@example.com",
    "http://127.1",
    "http://ur%20",
    "https://git.kernel.org/linus/a87938b2e246b81b4fb713edb371a9fa3c5c3c86",
    "https://github.com/curl/curl/commit/415d2e7cb7",
    "http://www.invedion.com",
    "http://www.invedion.com/",
    "http://support.oracle.com/CSP/main/article?cmd=show&type=NOT&id=2318213.1",
    "http://support.oracle.com/CSP/main/article?cmd=show&type=NOT&id=2310021.1",
    "https://www.joomlaextensions.co.in/",
    "http://demo.ynetinteractive.com/soa/",
    "http://demo.ynetinteractive.com/mobiketa/",
    "http://codecanyon.net/user/Endober",
    "http://speicher.example.com/envato/codecanyon/demo/web-file-explorer/download.php?id=WebExplorer/../config.php",
    "https://github.com/qbittorrent/qBittorrent/wiki/I-forgot-my-UI-lock-password",
    "https://domain/api/content/JavaStart.jar",
    "http://INTRANET-IP:8000",
    "https://electron.atom.io/docs/api/sandbox-option",
    "http://some.server.com//nodesecurity.org/%2e%2e",
    "https://wdune.ourproject.org/",
    "https://services.gradle.org/distributions/gradle-2.14.1-all.zip",
    "https://h-sdk.online-metrix.net",
    "http://x.x.x.x/setup/setup_maintain_firmware-default.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-execute.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-fetch.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-close.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-error.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-errno.html",
    "https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-sqlstate.html",
    "https://bugzilla.mozilla.org/show_bug.cgi?id=1167489#c9",
    "http://localhost:22"
]

def analyze():
    extractor = RegexExtractor()
    with open("urls_analysis.csv", "w", encoding="utf-8") as f:
        f.write("Value,Status,ExtractedVal\n")
        for i, url in enumerate(urls, 1):
            iocs = extractor.extract_iocs_from_text(url)
            extracted = [ioc['value'] for ioc in iocs if ioc['ioc_type'] == 'url']
            
            status = "Extracted" if extracted else "Filtered"
            val = extracted[0] if extracted else "None"
            f.write(f'"{url}","{status}","{val}"\n')

if __name__ == "__main__":
    analyze()
