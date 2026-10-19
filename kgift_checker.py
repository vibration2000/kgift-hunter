"""
K-Gift Checker v2.0 - 헌터 결과를 실제 웹페이지 본문과 다시 대조하는 검증 엔진 (Zero-Lie)
v1.0 대비 바뀐 점
  - 페이지 전체가 아니라 '본문'만 본다 (메뉴·머리글·바닥글·스크립트 제거 → "신청/참여" 같은 메뉴 글자로 통과하던 문제 해결)
  - 제목 키워드에서 연도(2026년)·회차(제13회)·지자체명(안양시)을 뺀다 (어느 페이지에나 있는 글자라 검사가 무의미했음)
  - 경품 이름 + 금액 + 인원 + 지급 표현이 '같은 구절(160자 안)'에 있어야 통과 (문서 아무 곳에나 있으면 통과하던 문제 해결)
  - 경품이 여러 개면 전부 대조 (v1.0은 첫 번째만 확인)
  - 헌터와 같은 방식(쿠키·EUC-KR 디코딩)으로 접속하고, 재접속이 실패하면 헌터가 읽은 HTML로 대조(리포트에 표시)
"""

import argparse
import datetime as dt
import http.cookiejar
import html as htmllib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
GROUND_WINDOW = 160   # 경품 이름·금액·인원이 이 글자 수 안에 함께 있어야 한다


# ======================================================== 1. 네트워크
def get_safe_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1:ALL:!DH")
    ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
    ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def safe_url(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        path = urllib.parse.quote(parts.path, safe="/%:@")
        query = urllib.parse.quote(parts.query, safe="=&?/%:@+$,")
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
    except Exception:
        return url.strip()


def decode_html(raw: bytes, ctype: str = "") -> str:
    enc = None
    m = re.search(r"charset=([\w\-]+)", ctype or "", re.I)
    if m:
        enc = m.group(1)
    if not enc:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w\-]+)", raw[:3000], re.I)
        if m:
            enc = m.group(1).decode("ascii", "ignore")
    for e in (enc, "utf-8", "cp949", "euc-kr"):
        if not e:
            continue
        try:
            return raw.decode(e)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


def fetch_page_html(url: str, referer: str = "", timeout: int = 12) -> tuple:
    """(상태코드, HTML, 에러) 반환. 쿠키·Referer·EUC-KR 디코딩을 헌터와 같게 처리."""
    if not url:
        return 0, "", "URL_EMPTY"
    hdr = {"User-Agent": UA,
           "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
           "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"}
    if referer:
        hdr["Referer"] = safe_url(referer)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         urllib.request.HTTPSHandler(context=get_safe_ssl_context()))
    try:
        with opener.open(urllib.request.Request(safe_url(url), headers=hdr), timeout=timeout) as res:
            return res.getcode(), decode_html(res.read(), res.headers.get("Content-Type", "")), ""
    except urllib.error.HTTPError as e:
        return e.code, "", f"HTTP_{e.code}"
    except urllib.error.URLError as e:
        return 0, "", f"URL_ERROR_{e.reason}"
    except Exception as e:
        return 0, "", f"EXCEPTION_{e}"


def body_text(html: str) -> str:
    """메뉴·머리글·바닥글·스크립트를 뺀 본문 글자만 한 줄로 만든다."""
    html = re.sub(r"(?is)<(script|style|noscript|nav|footer|header)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|dd|dt|td|th)>", "\n", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    lines = [re.sub(r"\s+", " ", l).strip() for l in text.split("\n")]
    return " ".join(l for l in lines if l)



# ======================================================== 1.5 포스터(가짜 사진 금지)
IMG_MAGIC = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF")   # jpg, png, gif, webp(RIFF)


def check_poster(ev_data: dict) -> tuple:
    """포스터는 필수. 비어 있거나 실제 이미지로 열리지 않으면 (False, 사유코드, 설명).
    앱이 스톡사진을 대신 보여주는 일이 없도록 '진짜 포스터가 있는 글'만 통과시킨다."""
    pu = str(ev_data.get("poster_image_url") or ev_data.get("posterUrl") or "").strip()
    if not pu:
        return False, "POSTER_MISSING", "포스터 이미지가 비어 있습니다."
    # 헌터가 PDF 첨부 1쪽을 그림으로 만들어 저장해 둔 경우 (커밋 전이라 URL 은 아직 안 열림)
    lp = ev_data.get("poster_local_path") or ""
    if lp:
        try:
            with open(lp, "rb") as f:
                head = f.read(16)
            if os.path.getsize(lp) > 2000 and head.startswith(IMG_MAGIC):
                return True, "OK_LOCAL", lp
        except Exception:
            pass
        return False, "POSTER_BROKEN", f"저장된 포스터 파일이 이미지가 아닙니다: {lp}"
    if not pu.lower().startswith(("http://", "https://")):
        return False, "POSTER_BROKEN", f"포스터 주소 형식이 올바르지 않습니다: {pu[:50]}"
    ref = ev_data.get("source_url") or ev_data.get("sourceUrl") or ""
    hdr = {"User-Agent": UA, "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"}
    if ref:
        hdr["Referer"] = safe_url(ref)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         urllib.request.HTTPSHandler(context=get_safe_ssl_context()))
    try:
        with opener.open(urllib.request.Request(safe_url(pu), headers=hdr), timeout=15) as res:
            head = res.read(4096)
            ct = res.headers.get("Content-Type", "").lower()
            code = res.getcode()
    except Exception as e:
        return False, "POSTER_BROKEN", f"포스터 이미지가 열리지 않습니다: {str(e)[:60]}"
    if code == 200 and len(head) > 500 and ("image" in ct or head.startswith(IMG_MAGIC)):
        return True, "OK", ct
    return False, "POSTER_BROKEN", f"포스터가 이미지가 아닙니다 ({code} {ct[:30]})"

# ======================================================== 2. 규칙
DETAIL_PARAM_PATTERNS = [
    r"seq=", r"seqno=", r"q_sn=", r"q_bbscttsn=", r"bidx=", r"bbscttsn=",
    r"cotid=", r"nttid=", r"nttno=", r"q_\w*sn=\d", r"articleno=", r"view\.do", r"notice_view",
    r"view\.php", r"view\.asp", r"forinsert", r"naver\.me", r"forms\.gle",
    r"/gongmo/\d+", r"/detail/", r"/view/\w+"
]

GENERIC_URL_BLACKLIST = [
    r"^https?://[^/]+/?$",
    r"/main(\.do)?$", r"/index(\.do)?$",
    r"ing-proposal", r"competitionlist\.do",
    r"selectbbslist\.do", r"board\.list\.do", r"selecteventcldrlist\.do",
    r"selectradondetectorlist", r"selectonlinereqstdoclist", r"selectpssrpbsnslist",
    r"gnews\.gg\.go\.kr", r"/news/news_detail\.do", r"/news/", r"/press/", r"/report/", r"article\.view",
]

# 지급 표현 (헌터의 GIVE_WORDS 와 같은 기준)
GIVE_WORDS = ["증정", "지급", "드립니다", "드려요", "추첨", "수여", "시상", "경품", "선물", "당첨", "받으실", "받을 수"]
COUNT_UNITS = ("명", "인", "개", "EA", "팀", "분")

GG_CITIES = ["수원", "고양", "용인", "성남", "부천", "화성", "안산", "남양주", "안양", "평택", "시흥", "파주", "의정부",
             "김포", "광명", "하남", "군포", "오산", "이천", "양주", "구리", "안성", "포천", "의왕", "양평", "여주",
             "동두천", "과천", "가평", "연천", "광주"]
REGION_WORDS = {"경기도", "경기", "특례시"} | {c + s for c in GG_CITIES for s in ("시", "군", "특례시")}

STOPWORDS = {"알림", "안내", "개최", "공고", "모집", "신청", "접수", "진행", "참여", "대한", "관련", "위한", "있는", "하는", "통한", "및", "등"}

NON_EVENT_TITLE_PATTERNS = [
    r"급식", r"취재지원자료", r"스타트업\s*서밋", r"보이스피싱", r"착한아파트",
    r"운영·관리\s*방침", r"현안사항\s*안내", r"공유재산", r"자료\s*공개",
    r"라돈측정기", r"임시휴원", r"유의사항\s*안내", r"의견수렴\s*창구",
    r"보도자료", r"브리핑", r"기자회견", r"간담회"
]

INVALID_REWARDS = [
    "무료", "0원", "0", "없음", "무상", "무보상", "해당없음", "단순안내", "단순 안내",
    "시민 참여 기념품 및 혜택", "기념품 및 혜택", "시민 참여 기념품", "기념품", "혜택",
    "참여 혜택", "기념품 증정"
]

ACTION_KEYWORDS = ["응모", "신청", "참여", "접수", "설문", "퀴즈", "서명", "출품", "제출", "작성"]

CLOSED_PATTERNS = [
    "접수가 마감되었습니다", "접수 마감되었습니다", "접수가 마감되었", "이벤트가 종료되었습니다",
    "마감된 공모전입니다", "행사가 종료되었습니다", "접수기간이 종료되었습니다", "접수가 종료되었습니다",
    "신청이 마감되었습니다", "마감된 행사입니다"
]


def check_url_structure(url: str) -> tuple:
    if not url:
        return False, "URL_EMPTY"
    lower_u = url.lower()
    for pat in GENERIC_URL_BLACKLIST:
        if re.search(pat, lower_u):
            return False, f"GENERIC_DIRECTORY_OR_NEWS_URL: '{url}'는 이벤트 상세가 아닌 뉴스/기사/목록 페이지입니다."
    if not any(re.search(pat, lower_u) for pat in DETAIL_PARAM_PATTERNS):
        return False, f"MISSING_DETAIL_IDENTIFIER: '{url}'는 게시글 식별자(seq, q_sn 등)가 없는 일반 페이지입니다."
    return True, "OK"


def extract_keywords_from_title(title: str) -> list:
    """제목에서 '이 글만의 단어'를 뽑는다. 연도·회차·지자체명은 어느 페이지에나 있으므로 뺀다."""
    out = []
    for w in re.findall(r"[가-힣a-zA-Z0-9]{2,}", title):
        if w in STOPWORDS or w in REGION_WORDS:
            continue
        if re.fullmatch(r"\d{4}년?|제?\d+(회|기|차|차수)|\d+년도?", w):
            continue
        out.append(w)
    return out


def money_forms(n: int) -> list:
    forms = {f"{n:,}원", f"{n}원"}
    if n % 10000 == 0:
        forms |= {f"{n // 10000}만원"}
    if n % 1000 == 0:
        forms |= {f"{n // 1000}천원"}
    return sorted(forms)


def ground_reward(text: str, item_name: str, price: int, count: int) -> tuple:
    """경품 이름·금액·인원·지급 표현이 GROUND_WINDOW 글자 안에 함께 있는 구절을 찾는다. (찾았는지, 근거 구절)"""
    compact = text.replace(" ", "")
    name = (item_name or "").replace(" ", "")
    if not name:
        return False, ""
    count_forms = [f"{count:,}{u}" for u in COUNT_UNITS] + [f"{count}{u}" for u in COUNT_UNITS]
    for pf in money_forms(price):
        start = 0
        while True:
            i = compact.find(pf, start)
            if i < 0:
                break
            start = i + 1
            win = compact[max(0, i - GROUND_WINDOW): i + len(pf) + GROUND_WINDOW]
            if (name in win and any(c in win for c in count_forms) and any(g in win for g in GIVE_WORDS)):
                return True, win
    return False, ""


# ======================================================== 3. 단일 이벤트 검증
def verify_single_event(ev_data: dict, debug: bool = False, extra_text: str = "", page_html: str = "") -> tuple:
    """(통과 여부, 리포트). page_html 은 헌터가 읽은 HTML — 재접속이 실패했을 때만 대신 쓰고 리포트에 표시한다."""
    title = ev_data.get("title", "")
    source_url = ev_data.get("source_url") or ev_data.get("sourceUrl") or ""
    apply_url = ev_data.get("apply_url") or ev_data.get("applyUrl") or ""
    rewards = ev_data.get("rewards") or []
    rewards = [r for r in rewards if isinstance(r, dict)] if isinstance(rewards, list) else []
    claimed_reward = rewards[0].get("item_name", "") if rewards else str(ev_data.get("reward", ""))

    report = {"title": title, "source_url": source_url, "apply_url": apply_url,
              "claimed_reward": claimed_reward, "stages": {}, "verdict": "REJECT", "reason": ""}

    # Stage 0: 경품 이름 유효성
    for r in (rewards or [{"item_name": claimed_reward}]):
        nm = str(r.get("item_name", "")).strip()
        if not nm or nm in INVALID_REWARDS:
            report["stages"]["0_reward_validity"] = {"pass": False, "detail": f"INVALID_REWARD: '{nm}'"}
            report["reason"] = f"ZERO_REWARD_REJECT: 경품이 '{nm}'(없음/무료/모호한 기념품)이라 실질 경품이 아닙니다."
            return False, report
    for r in rewards:
        try:
            p, c = int(r.get("unit_price") or 0), int(r.get("winners_count") or 0)
        except (TypeError, ValueError):
            p, c = 0, 0
        if p <= 0 or c <= 0:
            report["stages"]["0_reward_validity"] = {"pass": False, "detail": f"AMOUNT_UNKNOWN: {r.get('item_name')} {p}원 x {c}명"}
            report["reason"] = f"AMOUNT_UNKNOWN: 경품 '{r.get('item_name')}'의 금액·인원이 확인되지 않아 탈락합니다."
            return False, report
    report["stages"]["0_reward_validity"] = {"pass": True, "detail": [r.get("item_name") for r in rewards] or claimed_reward}

    # Stage 0.5: 기한
    today = dt.date.today()
    period = ev_data.get("period")
    raw_end = (period.get("end") if isinstance(period, dict) else "") or ev_data.get("end_date") or ""
    end_date = None
    if raw_end:
        try:
            end_date = dt.datetime.strptime(str(raw_end)[:10], "%Y-%m-%d").date()
        except Exception:
            end_date = None
    if end_date is None:
        m = re.findall(r"(\d{4})[.\-/년]\s*(\d{1,2})[.\-/월]\s*(\d{1,2})", f"{period if isinstance(period, str) else ''} {title}")
        if m:
            try:
                end_date = dt.date(*map(int, m[-1]))
            except Exception:
                pass
    if end_date and end_date < today:
        report["stages"]["0_date_validity"] = {"pass": False, "end_date": str(end_date), "today": str(today)}
        report["reason"] = f"EXPIRED_EVENT_REJECT: 기간이 이미 종료되었습니다. (종료일: {end_date}, 오늘: {today})"
        return False, report
    report["stages"]["0_date_validity"] = {"pass": True, "end_date": str(end_date) if end_date else "UNKNOWN"}

    for pat in NON_EVENT_TITLE_PATTERNS:
        if re.search(pat, title):
            report["stages"]["0_title_validity"] = {"pass": False, "pattern": pat}
            report["reason"] = f"NON_EVENT_TITLE: 제목에 단순 기사/행정공지 패턴('{pat}')이 있어 이벤트로 인정되지 않습니다."
            return False, report

    # Stage 0.8: 포스터 필수 (가짜/스톡 사진 금지)
    p_ok, p_code, p_detail = check_poster(ev_data)
    report["stages"]["0_poster"] = {"pass": p_ok, "detail": p_detail}
    if not p_ok:
        report["reason"] = f"{p_code}: {p_detail} 진짜 포스터가 없는 이벤트는 앱에 올리지 않습니다."
        return False, report

    # Stage 1: URL 구조
    target_url = source_url or apply_url
    url_ok, url_msg = check_url_structure(target_url)
    report["stages"]["1_url_structure"] = {"pass": url_ok, "detail": url_msg}
    if not url_ok:
        report["reason"] = url_msg
        return False, report

    # Stage 2: 재접속 (실패하면 헌터가 읽은 HTML 로 대조하되 리포트에 남긴다)
    status, html, err = fetch_page_html(target_url, referer=target_url)
    source = "refetch"
    if status != 200 and page_html:
        status, html, err, source = 200, page_html, f"재접속 실패({err}) → 헌터가 읽은 HTML로 대조", "hunter_html"
    page_text = body_text(html)
    # 본문이 포스터 이미지뿐인 게시글도 있으므로 길이 기준은 낮게 둔다 (메뉴를 뺀 본문 + 포스터에서 읽은 글자 합계 30자)
    enough = len(page_text) + len(extra_text or "") >= 30
    report["stages"]["2_http_reachability"] = {"pass": status == 200 and enough, "status_code": status,
                                               "text_length": len(page_text), "source": source, "error": err}
    if status != 200:
        report["reason"] = f"HTTP_FAILED: 상태코드 {status} ({err})"
        return False, report
    if not enough:
        report["reason"] = f"BODY_TOO_SHORT: 메뉴를 뺀 본문이 {len(page_text)}자뿐이라 대조할 글자가 없습니다."
        return False, report
    if extra_text:
        page_text = f"{page_text} {extra_text}"

    # Stage 3: 제목 고유 키워드가 본문에 있는가
    keywords = extract_keywords_from_title(title)
    found_keywords = [k for k in keywords if k in page_text]
    need = min(2, len(keywords)) if keywords else 0
    ok3 = bool(keywords) and len(found_keywords) >= max(need, 1)
    report["stages"]["3_title_grounding"] = {"pass": ok3, "target_keywords": keywords, "found_keywords": found_keywords}
    if not ok3:
        report["reason"] = f"TITLE_MISMATCH: 본문에 제목 고유 키워드({keywords[:4]})가 충분히 없습니다 (찾은 것: {found_keywords})."
        return False, report

    # Stage 4: 시민 참여 행동 안내 (본문에서)
    found_actions = [a for a in ACTION_KEYWORDS if a in page_text]
    report["stages"]["4_action_grounding"] = {"pass": bool(found_actions), "found": found_actions[:4]}
    if not found_actions:
        report["reason"] = "NO_ACTION_CALL: 본문에 응모/신청/참여/접수 안내가 없는 일반 공지입니다."
        return False, report

    for cp in CLOSED_PATTERNS:
        if cp in page_text:
            report["stages"]["4_closed_status"] = {"pass": False, "pattern": cp}
            report["reason"] = f"CLOSED_EVENT_PAGE: 본문에 '{cp}' 안내가 있어 종료된 이벤트로 판정되었습니다."
            return False, report

    # Stage 5: 경품 이름 + 금액 + 인원 + 지급 표현이 같은 구절에 있는가 (경품마다)
    evidences = []
    if rewards:
        for r in rewards:
            ok, ev = ground_reward(page_text, r["item_name"], int(r["unit_price"]), int(r["winners_count"]))
            claimed_ev = (r.get("evidence") or "").replace(" ", "")
            evidences.append({"item": r["item_name"], "pass": ok, "evidence": ev[:120],
                              "hunter_evidence_in_page": bool(claimed_ev) and claimed_ev in page_text.replace(" ", "")})
            if not ok:
                report["stages"]["5_reward_grounding"] = {"pass": False, "items": evidences}
                report["reason"] = (f"REWARD_NOT_GROUNDED: '{r['item_name']} {int(r['unit_price']):,}원 x {int(r['winners_count'])}명'이 "
                                    f"본문의 한 구절({GROUND_WINDOW}자 안)에서 지급 표현과 함께 확인되지 않습니다 (거짓 리워드 차단).")
                return False, report
        report["stages"]["5_reward_grounding"] = {"pass": True, "items": evidences}
    else:
        # 단건 CLI 테스트(문자열 경품만 있는 입력): 금액·인원을 모르므로 약식 검사이며 리포트에 표시
        ok = claimed_reward.replace(" ", "") in page_text.replace(" ", "")
        report["stages"]["5_reward_grounding"] = {"pass": ok, "mode": "name_only(약식)"}
        if not ok:
            report["reason"] = f"REWARD_MISMATCH: 본문에 '{claimed_reward}' 언급이 없습니다."
            return False, report

    report["verdict"] = "VERIFIED_PASS"
    first_ev = evidences[0]["evidence"] if evidences else ""
    report["reason"] = (f"본문 대조 통과 (제목 고유 키워드 {found_keywords[:3]}, 참여 행동 {found_actions[:2]}, "
                        f"경품 근거 구절: \"{first_ev[:70]}\", 대조 방식: {source})")
    return True, report


def verify_and_filter_events(events: list) -> tuple:
    passed, rejected = [], []
    for ev in events:
        ed = ev.get("event_data") if "event_data" in ev else ev
        ok, rep = verify_single_event(ed)
        if ok:
            ev["kchecker_verified"] = True
            ev["kchecker_verified_at"] = dt.datetime.now().isoformat()
            ev["kchecker_report"] = rep["reason"]
            passed.append(ev)
        else:
            ev["kchecker_verified"] = False
            ev["kchecker_reject_reason"] = rep["reason"]
            rejected.append(ev)
    return passed, rejected


# ======================================================== 4. CLI
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="K-Gift Checker v2.0")
    parser.add_argument("--file", default="events.json")
    parser.add_argument("--out", default="events_verified.json")
    parser.add_argument("--url", help="단일 URL 즉시 검증 테스트")
    parser.add_argument("--title", default="테스트 공모전")
    parser.add_argument("--reward", default="상품권")
    args = parser.parse_args()

    print("=" * 65)
    print("[*] K-Gift Checker v2.0 가동 - 본문 대조 검증")
    print(f"[*] 실행 시각: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 65)

    if args.url:
        ok, rep = verify_single_event({"title": args.title, "source_url": args.url, "reward": args.reward}, debug=True)
        print(f"판정 결과: {'[VERIFIED_PASS] 통과' if ok else '[REJECT] 탈락'}")
        print(f"사유: {rep['reason']}")
        print(json.dumps(rep["stages"], ensure_ascii=False, indent=2))
        return

    file_path = os.path.join(HERE, args.file)
    if not os.path.exists(file_path):
        print(f"[-] 파일이 존재하지 않습니다: {file_path}")
        return
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    raw_events = data.get("events", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    print(f"[*] 검증 대상 이벤트 총 {len(raw_events)}건 로드 완료.")
    passed, rejected = verify_and_filter_events(raw_events)
    print(f"    - 승인 {len(passed)}건 / 탈락 {len(rejected)}건")
    for r in rejected:
        ed = r.get("event_data", r)
        print(f"  [탈락] {ed.get('title', '')[:35]} -> {r.get('kchecker_reject_reason')}")
    for p in passed:
        ed = p.get("event_data", p)
        print(f"  [승인] {ed.get('title', '')[:35]} -> {p.get('kchecker_report')}")
    out = {"status": "success", "verified_by": "K-Gift Checker v2.0", "verified_at": dt.datetime.now().isoformat(),
           "total_checked": len(raw_events), "passed_count": len(passed), "rejected_count": len(rejected), "events": passed}
    with open(os.path.join(HERE, args.out), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[*] 저장 완료: {args.out}")


if __name__ == "__main__":
    main()
