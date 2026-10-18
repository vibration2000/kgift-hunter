"""
GitHub Actions 해외 IP 접속 가능 여부 진단 스크립트
- GitHub Actions 환경(미국/유럽 등 해외 IP)에서 지자체 공공 사이트 방화벽 차단 여부(Geo-blocking) 판별
- SSL 레거시 우회 및 공공기관 웹 표준 헤더를 탑재하여 실제 수집 가능 여부 확인
"""

import sys
import ssl
import time
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
import os

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

TARGETS = [
    {"name": "수원특례시 참여행사", "url": "https://www.suwon.go.kr/web/board/BD_board.list.do?bbsCd=1381"},
    {"name": "고양특례시 설문조사", "url": "https://www.goyang.go.kr/www/user/qestnar/BD_selectQestnarList.do"},
    {"name": "용인특례시 시민참여", "url": "https://www.yongin.go.kr/citizen/user/bbs/BD_selectBbsList.do?q_bbsCode=1294"},
    {"name": "성남시 행사보기", "url": "https://www.seongnam.go.kr/pm010201?nowym="},
    {"name": "안양시 행사교육", "url": "https://www.anyang.go.kr/main/selectBbsNttList.do?bbsNo=63&key=261"},
    {"name": "화성특례시 행사일정", "url": "https://www.hscity.go.kr/www/user/eventCldr/BD_selectEventCldrList.do"},
    {"name": "경기도 뉴스포털", "url": "https://gnews.gg.go.kr"},
    {"name": "경기도 공모전 메인", "url": "https://www.gg.go.kr/gongmo"},
    {"name": "경기문화재단 문화행사", "url": "https://ggc.ggcf.kr"},
    {"name": "경기도 여론조사", "url": "https://survey.gg.go.kr/app/cscenter/infoGrList.do?bbsSn=3"},
    {"name": "Supabase REST API", "url": "https://pvcarkmnbttcgosmhwng.supabase.co/rest/v1/events?select=id&limit=1"}
]


def get_safe_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1:ALL:!DH")
    ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
    ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def check_site(name: str, url: str) -> dict:
    ctx = get_safe_ssl_context()
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx)
    )

    hdr = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
        "Referer": url
    }
    if "supabase.co" in url:
        hdr["apikey"] = "sb_publishable_o1WcoXAZ2aIwZdKqkOO0lg_VxBt6CeZ"
        hdr["Authorization"] = "Bearer sb_publishable_o1WcoXAZ2aIwZdKqkOO0lg_VxBt6CeZ"

    req = urllib.request.Request(url, headers=hdr)
    t0 = time.time()
    try:
        with opener.open(req, timeout=12) as resp:
            code = resp.getcode()
            body = resp.read(8192)
            elapsed = round(time.time() - t0, 2)
            # 해외 IP 차단 안내 문구 검출
            text_peek = body.decode("utf-8", errors="ignore") + body.decode("cp949", errors="ignore")
            if any(k in text_peek for k in ["해외", "접속이 차단", "차단되었습니다", "Access Denied", "Forbidden", "비정상적인 접근"]):
                return {"name": name, "url": url, "code": code, "status": "GEO_BLOCKED", "elapsed": elapsed, "detail": "본문 내 해외접속/접근차단 경고 발견"}
            return {"name": name, "url": url, "code": code, "status": "OK", "elapsed": elapsed, "detail": f"정상 응답 ({len(body)}B 수신)"}
    except urllib.error.HTTPError as e:
        elapsed = round(time.time() - t0, 2)
        if e.code in (403, 401, 406):
            return {"name": name, "url": url, "code": e.code, "status": "BLOCKED (403/401)", "elapsed": elapsed, "detail": f"HTTP {e.code} 차단"}
        return {"name": name, "url": url, "code": e.code, "status": f"HTTP_{e.code}", "elapsed": elapsed, "detail": f"HTTP 에러 {e.code}"}
    except urllib.error.URLError as e:
        elapsed = round(time.time() - t0, 2)
        reason_str = str(e.reason)
        if "timed out" in reason_str.lower():
            return {"name": name, "url": url, "code": 0, "status": "TIMEOUT", "elapsed": elapsed, "detail": "방화벽 타임아웃(패킷 드랍 의심)"}
        return {"name": name, "url": url, "code": 0, "status": "CONN_FAIL", "elapsed": elapsed, "detail": reason_str[:50]}
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        return {"name": name, "url": url, "code": 0, "status": "ERROR", "elapsed": elapsed, "detail": str(e)[:50]}


def main():
    print("=" * 70)
    print("🌐 지자체 공공 사이트 접속성 및 해외 IP 차단(Geo-blocking) 진단")
    print(f"[*] 진단 시각: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = []
    for target in TARGETS:
        res = check_site(target["name"], target["url"])
        results.append(res)
        icon = "✅" if res["status"] == "OK" else "❌"
        print(f"{icon} [{res['status']}] {res['name']:<18} ({res['elapsed']}s) - {res['detail']}")
        time.sleep(0.3)

    ok_count = sum(1 for r in results if r["status"] == "OK")
    fail_count = len(results) - ok_count

    print("=" * 70)
    print(f"📊 진단 결과 요약: 전체 {len(results)}개 중 성공 {ok_count}개 / 차단 및 실패 {fail_count}개")
    print("=" * 70)

    # GitHub Actions Step Summary 출력 지원
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## 🌐 지자체 공공 사이트 해외 IP(GitHub Actions) 접속 진단 결과\n\n")
            f.write(f"- **진단 일시**: {time.strftime('%Y-%m-%d %H:%M:%S')} (UTC)\n")
            f.write(f"- **성공률**: {ok_count}/{len(results)} (성공: {ok_count}, 차단/실패: {fail_count})\n\n")
            f.write("| 대상 지자체 | 상태 | 응답코드 | 소요시간 | 상세 내용 |\n")
            f.write("| :--- | :---: | :---: | :---: | :--- |\n")
            for r in results:
                icon = "✅ 정상" if r["status"] == "OK" else f"❌ {r['status']}"
                f.write(f"| [{r['name']}]({r['url']}) | {icon} | {r['code']} | {r['elapsed']}s | {r['detail']} |\n")

            f.write("\n### 💡 아키텍처 판단 가이드\n")
            if ok_count == len(results):
                f.write("> **[판정]** 전 지자체 접속 성공! GitHub Actions 환경에서 `kgift_hunter.py` 및 서버리스 Tesseract OCR 직접 운영이 가능합니다.\n")
            elif ok_count >= len(results) * 0.7:
                f.write("> **[판정]** 일부 지자체만 차단됨. 차단 사이트는 국내 로컬에서 수집하고, 나머지는 GitHub Actions로 분산 가능합니다.\n")
            else:
                f.write("> **[판정]** 대다수 지자체가 해외 IP를 차단(Geo-blocking) 중입니다. 크롤링 및 OCR은 국내 IP(로컬 PC 또는 국내 클라우드 리전)에서 실행하고 결과(JSON)만 GitHub/Supabase에 푸시하는 구조를 채택해야 합니다.\n")

    # 모든 사이트가 403/TIMEOUT 등으로 차단되면 exit code 1
    if ok_count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
