"""
K-Gift Hunter v2.0 - 경기지역 시민참여 이벤트 수집 엔진 (독립 실행)

흐름: sources_gyeonggi.json(수집 대상) -> 목록 페이지 -> 이벤트 링크 선별 -> 상세 페이지 추출
      -> 필터(공모전 제외 / 마감 제외 / 경기 지역) -> events.json 저장 -> (선택) Supabase 적재

사용 예)
  python kgift_hunter.py --no-sync                       # sources 파일 전체 수집, JSON만 저장
  python kgift_hunter.py --list-url https://...  --no-sync   # 목록 페이지 하나만 수집
  python kgift_hunter.py --url https://...  --no-sync        # 이벤트 상세 페이지 하나만 추출
  python kgift_hunter.py --html-file saved.html --no-sync    # 저장해 둔 HTML 파일로 테스트(인터넷 불필요)
  python kgift_hunter.py                                 # 수집 + Supabase 전송

출력 events.json: 기존 HTML 앱과 호환되도록 최상단에 event_data(대표 1건)가 있고,
                  전체 목록은 events 배열에 들어갑니다.
"""

import argparse
import datetime as dt
import hashlib
import html as htmllib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import zipfile
import http.cookiejar
from collections import Counter

VERSION = "2.1"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SOURCES = os.path.join(HERE, "sources_gyeonggi.json")
DEFAULT_SB_URL = "https://pvcarkmnbttcgosmhwng.supabase.co"
DEFAULT_SB_KEY = "sb_publishable_o1WcoXAZ2aIwZdKqkOO0lg_VxBt6CeZ"  # 공개용(publishable) 키만 사용
OWNER_ID = "67e6f52e-f5f8-44e6-9179-7b38740d38ab"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

GG_CITIES = ["수원", "성남", "의정부", "안양", "부천", "광명", "평택", "동두천", "안산", "고양", "과천", "구리",
             "남양주", "오산", "시흥", "군포", "의왕", "하남", "용인", "파주", "이천", "안성", "김포", "화성",
             "광주", "양주", "포천", "여주", "연천", "가평", "양평"]

# 시민이 참여하는 이벤트임을 나타내는 말 / 제외할 말
JOIN_WORDS = ["이벤트", "응모", "퀴즈", "설문", "댓글", "인증", "챌린지", "SNS", "후기", "참여하세요", "참여 이벤트", "경품", "추첨",
              # 경품 없는 참여형 행사
              "행사", "축제", "체험", "참가자", "참여자", "시민참여", "참여 안내", "참가 신청", "투표", "캠페인", "걷기", "마라톤",
              "클래스", "원데이", "설명회", "토론회", "워크숍", "페스티벌", "대회", "접수"]
NAV_WORDS = ["다음", "이전", "목록", "로그인", "회원가입", "더보기", "맨앞", "맨뒤", "처음", "마지막", "검색", "사이트맵"]
EXCLUDE_WORDS = ["공모전", "공모 ", "작품 공모", "채용", "입찰", "용역", "입찰공고", "사업자 모집", "강사 모집"]
REWARD_WORDS = ["상품권", "기프티콘", "커피", "치킨", "문화상품권", "지역화폐", "경기지역화폐", "굿즈", "기념품", "쿠폰", "포인트", "추첨"]


# ======================================================== 공통 유틸
class Net:
    def __init__(self, insecure=False, delay=1.0, respect_robots=True):
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.delay = delay
        self.respect_robots = respect_robots
        self._robots = {}
        self._last = 0.0
        self.jar = http.cookiejar.CookieJar()  # 접속 확인(checker) 페이지가 쿠키를 심는 사이트 대응
        self.fails = Counter()  # 호스트별 연속 접속 실패 횟수 (응답 없는 사이트는 빨리 포기)

    def _open(self, req, ctx, timeout):
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                         urllib.request.HTTPSHandler(context=ctx))
        with op.open(req, timeout=timeout) as resp:
            return resp.read(), resp.headers.get("Content-Type", "")

    @staticmethod
    def client_redirect(html, base_url):
        """HTTP 가 아닌 <meta refresh> / JS location 이동을 찾아 다음 주소를 돌려줌 (짧은 페이지만)"""
        if len(html) > 9000:
            return None
        m = re.search(r'http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)', html, re.I) \
            or re.search(r'(?:document\.|window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', html, re.I)
        return urllib.parse.urljoin(base_url, htmllib.unescape(m.group(1))) if m else None

    def allowed(self, url):
        if not self.respect_robots:
            return True
        p = urllib.parse.urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        if base not in self._robots:
            rp = urllib.robotparser.RobotFileParser()
            try:
                req = urllib.request.Request(base + "/robots.txt", headers={"User-Agent": UA})
                with urllib.request.urlopen(req, context=self.ctx, timeout=6) as r:
                    rp.parse(r.read().decode("utf-8", errors="ignore").splitlines())
            except Exception:
                rp = None  # robots.txt 없음/실패 -> 허용
            self._robots[base] = rp
        rp = self._robots[base]
        return True if rp is None else rp.can_fetch(UA, url)

    def get(self, url):
        host = urllib.parse.urlparse(url).netloc
        if self.fails[host] >= 2:
            raise ConnectionError("응답 없음: 같은 사이트에서 연속 접속 실패로 건너뜀")
        try:
            html = self._get(url)
            self.fails[host] = 0
            return html
        except urllib.error.HTTPError:
            raise  # 404 등 개별 페이지 오류는 사이트 전체 문제가 아님
        except PermissionError:
            raise
        except Exception:
            self.fails[host] += 1
            raise

    def _get(self, url):
        if not self.allowed(url):
            raise PermissionError("robots.txt 에서 수집을 허용하지 않는 페이지")
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        html, prev = "", None
        for _ in range(4):  # 최대 3번까지 자동 이동 따라가기
            hdr = {"User-Agent": UA, "Accept-Language": "ko-KR,ko;q=0.9",
                   "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
            if prev:
                hdr["Referer"] = prev
            req = urllib.request.Request(url, headers=hdr)
            try:
                raw, ctype = self._open(req, self.ctx, 10)
            except (ssl.SSLError, urllib.error.URLError, ConnectionError) as e:
                # 일부 공공기관 서버는 구형 TLS 설정이라 기본 연결이 끊김 -> 완화된 설정으로 1회 재시도
                if "SSL" not in str(e) and not isinstance(e, ssl.SSLError):
                    raise
                raw, ctype = self._open(req, legacy_ctx(), 10)
            html = decode_html(raw, ctype)
            nxt = self.client_redirect(html, url)
            if not nxt or nxt == url:
                break
            prev, url = url, nxt
        self._last = time.time()
        return html


def legacy_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    try:
        c.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    return c


def decode_html(raw: bytes, ctype: str = "") -> str:
    """UTF-8 / EUC-KR(CP949) 자동 판별 (공공기관 사이트는 EUC-KR이 아직 많음)"""
    enc = None
    m = re.search(r"charset=([\w\-]+)", ctype, re.I)
    if m:
        enc = m.group(1)
    if not enc:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w\-]+)", raw[:3000], re.I)
        if m:
            enc = m.group(1).decode("ascii", "ignore")
    for e in [enc, "utf-8", "cp949"]:
        if not e:
            continue
        try:
            return raw.decode(e)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


def clean_text(html: str) -> list:
    html = re.sub(r"(?is)<(script|style|noscript|nav|footer|header)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|dd|dt|td|th)>", "\n", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    lines = [re.sub(r"\s+", " ", l).strip() for l in text.split("\n")]
    return [l for l in lines if l]


def meta(html: str, prop: str) -> str:
    for pat in (rf'<meta[^>]+(?:property|name)=["\']{prop}["\'][^>]+content=["\']([^"\']*)["\']',
                rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']{prop}["\']'):
        m = re.search(pat, html, re.I)
        if m:
            return htmllib.unescape(m.group(1)).strip()
    return ""


# ======================================================== 1. 목록 페이지 -> 이벤트 링크
def resolve_js_link(onclick: str, list_url: str):
    """href="#" + onclick="jsView('게시판코드','글번호')" 형태(수원시 등)를 실제 상세 주소로 변환"""
    m = re.search(r"\w*(?:[vV]iew|[dD]etail|[rR]ead)\w*\(\s*['\"]?(\w+)['\"]?\s*,\s*['\"]?(\w+)['\"]?", onclick or "")
    if not m:
        return None
    a, b = m.group(1), m.group(2)
    p = urllib.parse.urlparse(list_url)
    if "BD_board.list.do" in p.path:  # openworks 계열 (수원시)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path.replace("BD_board.list.do", "BD_board.view.do"),
                                        "", f"bbsCd={a}&seq={b}", ""))
    return None


def find_event_links(list_html: str, list_url: str, keywords=None, limit=30, accept_all=False) -> list:
    """accept_all=True: 이미 '행사/이벤트 게시판'인 목록은 키워드 없이 게시글 링크를 전부 후보로 삼음"""
    keywords = keywords or JOIN_WORDS
    found, seen = [], set()
    # 목록 주소의 게시판 코드(bbsCd=1381, q_bbsCode=1007 등)가 들어간 링크만 = 같은 게시판의 글
    board_codes = [v for k, v in urllib.parse.parse_qsl(urllib.parse.urlparse(list_url).query)
                   if re.search(r"bbs|board", k, re.I) and v]
    for attrs, inner in re.findall(r'<a\b([^>]*)>(.*?)</a>', list_html, re.S | re.I):
        hm = re.search(r'href=(["\'])(.*?)\1', attrs, re.I | re.S)
        om = re.search(r'onclick=(["\'])(.*?)\1', attrs, re.I | re.S)  # 값 안의 ' 를 안전하게 처리
        href = hm.group(2) if hm else ""
        text = re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", inner))).strip()
        if href.startswith(("javascript", "#")) or not href:
            href = resolve_js_link(htmllib.unescape(om.group(2)) if om else href, list_url) or ""
        if not href or len(text) < 6 or href.startswith(("mailto", "tel")) or text in NAV_WORDS:
            continue
        if accept_all:
            # 게시글 상세로 보이는 링크만 (view/detail/Bbs 등)
            if not re.search(r"view|detail|select|seq|idx|sn=|bbscttsn|nttid|articleno", href, re.I):
                continue
            if board_codes and not any(c in href for c in board_codes):
                continue
        elif not any(k in text for k in keywords):
            continue
        if any(x in text for x in EXCLUDE_WORDS):
            continue
        url = urllib.parse.urljoin(list_url, htmllib.unescape(href))
        if url in seen:
            continue
        seen.add(url)
        found.append({"url": url, "link_text": text})
        if len(found) >= limit:
            break
    return found


# ======================================================== 2. 상세 페이지 -> 정형 데이터
DATE_PATTERNS = [
    # 2026.10.13 ~ 2026.10.19 / 2026-10-13 ~ 10-19 / 2026. 10. 13.(월) ~ 10. 19.
    r"(\d{4})\s*[.\-/년]\s*(\d{1,2})\s*[.\-/월]\s*(\d{1,2})\s*[일.]?\s*(?:\([가-힣]\))?\s*(?:\d{1,2}\s*:\s*\d{2})?\s*[~\-–∼]\s*(?:(\d{4})\s*[.\-/년]\s*)?(\d{1,2})\s*[.\-/월]\s*(\d{1,2})",
    # 10월 13일 ~ 10월 19일
    r"()(\d{1,2})\s*월\s*(\d{1,2})\s*일\s*(?:\([가-힣]\))?\s*(?:\d{1,2}\s*:\s*\d{2})?\s*(?:[~\-–∼]|부터)\s*()(?:(\d{1,2})\s*월\s*)?(\d{1,2})\s*일",
]


def parse_period(text: str, today: dt.date):
    for pat in DATE_PATTERNS:
        for m in re.finditer(pat, text):
            y1, m1, d1, y2, m2, d2 = m.groups()
            try:
                y1 = int(y1) if y1 else today.year
                y2 = int(y2) if y2 else y1
                m2 = m2 or m1
                start = dt.date(y1, int(m1), int(d1))
                end = dt.date(y2, int(m2), int(d2))
                if end < start:
                    end = dt.date(y2 + 1, int(m2), int(d2))
                return start, end
            except ValueError:
                continue
    # 단일 날짜(행사 일시): "일시 2026. 10. 25.(토)" -> 시작=종료
    m = re.search(r"(?:일시|일자|행사일|개최일|운영일|일정)[^0-9]{0,6}(\d{4})\s*[.\-/년]\s*(\d{1,2})\s*[.\-/월]\s*(\d{1,2})", text)
    if m:
        try:
            d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return d, d
        except ValueError:
            pass
    return None, None


def parse_rewards(text: str) -> list:
    rewards = []
    # "서울사랑상품권 5,000원 100명" 류: 경품명 + 금액 + 인원
    for m in re.finditer(r"([가-힣A-Za-z0-9 ]{0,12}(?:상품권|기프티콘|쿠폰|커피|치킨|지역화폐|굿즈|기념품|포인트))[^0-9]{0,15}?(\d[\d,]*)\s*(원|만원)?[^0-9]{0,20}?(\d[\d,]*)\s*(명|名)", text):
        name, amt, unit, cnt, _ = m.groups()
        amount = int(amt.replace(",", "")) * (10000 if unit == "만원" else 1)
        count = int(cnt.replace(",", ""))
        if 0 < count < 100000:
            rewards.append({"item_name": name.strip(), "unit_price": amount if unit else 0,
                            "winners_count": count})
    if not rewards:
        for w in REWARD_WORDS:
            if w in text:
                m = re.search(rf"{w}[^\n]{{0,25}}?(\d[\d,]*)\s*명", text)
                rewards.append({"item_name": w, "unit_price": 0,
                                "winners_count": int(m.group(1).replace(",", "")) if m else 0})
                break
    return rewards[:5]


def _suffix(c):
    return "군" if c in ("가평", "양평", "연천") else "시"


def guess_region(text: str, org_hint: str = "", title: str = "") -> tuple:
    """기관명 > 제목 > 본문에서 가장 많이 나온 시군 순서로 판단 (본문에 다른 시가 한 번 나온다고 바꾸지 않음)"""
    for src in (org_hint, title):
        for c in GG_CITIES:
            if f"{c}시" in src or f"{c}군" in src:
                return f"경기도 {c}", f"{c}{_suffix(c)}"
    body = text[:6000]
    counts = {c: body.count(f"{c}시") + body.count(f"{c}군") for c in GG_CITIES}
    best = max(counts, key=counts.get)
    if counts[best] >= 3:
        return f"경기도 {best}", f"{best}{_suffix(best)}"
    if "경기" in (org_hint + title + body):
        return "경기도", "경기도"
    return "", ""


def extract_event(html: str, source_url: str, org_hint: str = "", today=None) -> dict:
    today = today or dt.date.today()
    lines = clean_text(html)
    full = " ".join(lines)

    title = meta(html, "og:title")
    if not title:
        m = re.search(r"<h[12][^>]*>(.*?)</h[12]>", html, re.S | re.I)
        if m:
            title = re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", m.group(1)))).strip()
    if not title:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
        title = htmllib.unescape(m.group(1)).strip() if m else ""
    title = re.sub(r"\s+", " ", title).strip()
    title = re.split(r"\s+:\s+[가-힣]+(?:시청|청)\s*>|\s+[|｜]\s+(?:지금경기|경기관광)", title)[0]
    title = re.sub(r"\s*[|\-–]\s*(경기도|[가-힣]+(시|군)(청)?)[^|]*$", "", title).strip() or "제목 확인 필요"

    poster = meta(html, "og:image")
    if poster:
        poster = urllib.parse.urljoin(source_url, poster)
    else:
        for img in re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
            if re.search(r"\.(jpg|jpeg|png|webp)", img, re.I) and not re.search(r"icon|logo|btn|blank", img, re.I):
                poster = urllib.parse.urljoin(source_url, img)
                break

    apply_url = source_url
    for href, inner in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.S | re.I):
        t = re.sub(r"<[^>]+>", "", inner)
        h = htmllib.unescape(href)
        if any(d in h for d in ("naver.me", "forms.gle", "form.naver.com", "docs.google.com/forms", "surveymonkey", "smartstore")) \
                or re.search(r"응모|신청하기|참여하기|바로가기|설문", t):
            if h.startswith("http"):
                apply_url = h
                break

    start, end = parse_period(full, today)
    rewards = parse_rewards(full)
    region, org = guess_region(full, org_hint, title)
    abuse = next((l for l in lines if any(k in l for k in ("중복 응모", "중복 참여", "명의도용", "부정", "당첨이 취소", "1인 1회"))), "")

    # 유형 분류: 경품이 없어도 '참여형 행사'로 인정
    head = title + " " + full[:2000]
    if rewards and any(w in head for w in ("이벤트", "응모", "추첨", "경품")):
        category = "경품 이벤트"
    elif any(w in head for w in ("설문", "퀴즈", "투표", "의견")):
        category = "설문·퀴즈·투표"
    elif any(w in head for w in ("행사", "축제", "체험", "페스티벌", "캠페인", "걷기", "마라톤", "대회", "클래스", "설명회", "토론회", "워크숍")):
        category = "참여형 행사"
    else:
        category = "시민참여 / 기타"

    # 점수: 얼마나 '시민 참여 이벤트·행사'다운지 (경품은 있으면 가산점, 없어도 감점 없음)
    score = 0
    score += 30 if any(w in title for w in JOIN_WORDS) else (10 if any(w in head for w in JOIN_WORDS) else 0)
    score += 20 if start else 0
    score += 15 if rewards else 0
    score += 5 if re.search(r"신청|접수|참가|참여", full[:3000]) else 0
    score += 15 if region else 0
    score += 10 if apply_url != source_url else 0
    score += 5 if poster else 0

    if not any(w in title for w in JOIN_WORDS) and not rewards:
        score = min(score, 40)  # 제목에 이벤트/행사 단어가 없는 일반 공지(운영 안내 등)는 제외 대상
    is_contest = any(w in title for w in EXCLUDE_WORDS)
    no_date = start is None
    expired = bool(end and end < today)

    dedup = hashlib.sha256(f"{org or org_hint}:{title}:{start}:{end}".encode("utf-8")).hexdigest()
    return {
        "status": "success",
        "confidence_score": score,
        "dedup_hash": dedup,
        "skip_reason": "공모전/비참여형" if is_contest else ("마감됨" if expired else ("기간 확인 불가" if no_date else "")),
        "event_data": {
            "title": title,
            "org_name": org_hint or org or "경기도",
            "category": category,
            "target_region": region or "경기도",
            "target_age": ["ALL"],
            "period": {
                "start": start.isoformat() if start else "",
                "end": end.isoformat() if end else "",
                "active_round": "", "next_round": "", "total_rounds": "",
            },
            "rewards": rewards or [{"item_name": "경품 없음(참여형)", "winners_count": 0, "unit_price": 0}],
            "source_url": source_url,
            "apply_url": apply_url,
            "poster_image_url": poster,
            "abuse_prevention_rule": abuse or "",
            "announcement_info": "",
        },
    }


# ======================================================== 3. 수집 실행 (자동 탐색 · 재시도 · 진단)
MENU_WORDS = ["이벤트", "참여마당", "시민참여", "행사", "축제", "설문", "참여", "시민마당", "알림마당"]
MENU_SCORE = {"이벤트": 5, "행사": 4, "축제": 3, "참여마당": 3, "시민참여": 3, "설문": 2, "시민마당": 1, "알림마당": 1, "참여": 1}


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def load_sources(path):
    d = load_json(path, {})
    return ([s for s in d.get("sources", []) if s.get("enabled", True)],
            [h for h in d.get("homepages", []) if h.get("enabled", True)])


def discover_boards(net, home_url, max_boards=4):
    """시청 첫 화면 메뉴에서 '이벤트/행사/참여' 게시판 링크를 자동으로 찾는다"""
    html = net.get(home_url)
    host = urllib.parse.urlparse(home_url).netloc.split(":")[0]
    root = ".".join(host.split(".")[-3:])
    cands, seen = [], set()
    for href, inner in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.S | re.I):
        text = re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", inner))).strip()
        if not (2 <= len(text) <= 24) or href.startswith(("javascript", "#", "mailto", "tel")):
            continue
        if not any(w in text for w in MENU_WORDS) or any(x in text for x in EXCLUDE_WORDS + ["공모", "채용", "입찰", "고시"]):
            continue
        url = urllib.parse.urljoin(home_url, htmllib.unescape(href))
        if not urllib.parse.urlparse(url).netloc.split(":")[0].endswith(root) or url in seen:
            continue
        seen.add(url)
        cands.append({"text": text, "url": url, "score": max(MENU_SCORE[w] for w in MENU_WORDS if w in text)})
    cands.sort(key=lambda c: -c["score"])
    if not cands:
        save_debug(home_url, html, "home")  # 메뉴를 못 찾았을 때 진단용으로 첫 화면 저장
    return cands[:max_boards]


def collect_from_list(net, list_url, org, keywords, max_items, today, accept_all=False):
    st = {"error": "", "candidates": 0}
    out, log, lh = [], [], ""
    try:
        lh = net.get(list_url)
    except Exception as e:
        st["error"] = str(e)
        return out, [f"  [-] 목록 접근 실패: {e}"], st, lh
    links = find_event_links(lh, list_url, keywords, max_items, accept_all)
    st["candidates"] = len(links)
    log.append(f"  [*] 이벤트 후보 링크 {len(links)}개 ({'게시판 전체' if accept_all else '키워드'} 방식)")
    for it in links:
        try:
            dh = net.get(it["url"])
        except Exception as e:
            log.append(f"    [-] {it['url']} 실패: {e}")
            continue
        ev = extract_event(dh, it["url"], org, today)
        if ev["event_data"]["title"] == "제목 확인 필요":
            ev["event_data"]["title"] = it["link_text"]
        ev["_html"] = dh
        out.append(ev)
    return out, log, st, lh


def smart_collect(net, t, max_items, today):
    """한 방식으로 후보가 0개면 반대 방식으로 자동 재시도"""
    mode = t.get("accept_all", False)
    out, log, st, lh = collect_from_list(net, t["list_url"], t.get("org", ""), t.get("keywords"), max_items, today, mode)
    if not st["error"] and st["candidates"] == 0:
        log.append("  [~] 후보 0개 -> 반대 방식으로 자동 재시도")
        out, log2, st, lh = collect_from_list(net, t["list_url"], t.get("org", ""), t.get("keywords"), max_items, today, not mode)
        log += log2
    return out, log, st, lh


def save_debug(name, html, tag="list"):
    d = os.path.join(HERE, "debug")
    os.makedirs(d, exist_ok=True)
    fn = re.sub(r"[^0-9A-Za-z가-힣]+", "_", name)[:40] + f"_{tag}.html"
    with open(os.path.join(d, fn), "w", encoding="utf-8") as f:
        f.write(html or "")
    return os.path.join("debug", fn)


def filter_and_dedup(results, min_score):
    kept, seen, dropped = [], set(), []
    for r in results:
        t, src = r["event_data"]["title"], r.get("_source", "")
        if r["skip_reason"]:
            dropped.append((t, r["skip_reason"], src))
        elif r["confidence_score"] < min_score:
            dropped.append((t, f"신뢰도 낮음({r['confidence_score']})", src))
        elif r["dedup_hash"] in seen:
            dropped.append((t, "중복", src))
        else:
            seen.add(r["dedup_hash"])
            kept.append(r)
    kept.sort(key=lambda r: -r["confidence_score"])
    return kept, dropped


def save_json(events, path):
    pub = [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]
    out = {"status": "success", "version": VERSION, "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
           "count": len(pub), "events": pub}
    if pub:  # 기존 HTML 앱(단건 불러오기) 호환: 대표 1건을 최상단에도 둠
        out.update({k: pub[0][k] for k in ("confidence_score", "dedup_hash", "event_data")})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[*] 로컬 JSON 저장 완료: {path} ({len(pub)}건)")


def advise(row):
    e = row["error"]
    if e:
        if "robots" in e:
            return "robots.txt 가 자동 수집을 허용하지 않아 제외했습니다 (정책 준수)."
        if "SSL" in e or "EOF" in e:
            return "서버가 접속을 끊었습니다(보안 설정/차단). 이 사이트는 이번에는 수집 불가."
        if any(c in e for c in ("403", "404", "500")):
            return f"주소 오류 또는 접근 거부({e[:40]}). 게시판 주소를 확인해야 합니다."
        return f"접속 실패: {e[:60]}"
    if row["candidates"] == 0:
        return f"이벤트 링크를 못 찾음. 페이지를 {row.get('debug', 'debug 폴더')} 에 저장했습니다 (구조 확인 필요)."
    if row["kept"] == 0:
        top = ", ".join(f"{k} {v}건" for k, v in row["reasons"].most_common(3)) or "원인 불명"
        return f"후보는 있었으나 전부 제외됨 ({top}). 샘플은 {row.get('debug', 'debug 폴더')}."
    return "정상"


def write_report(path, rows, kept, dropped):
    lines = [f"K-Gift Hunter v{VERSION} 진단 리포트  {dt.datetime.now():%Y-%m-%d %H:%M}",
             f"결과: 사용 {len(kept)}건 / 제외 {len(dropped)}건", "=" * 60]
    for r in rows:
        mark = "OK " if (r["kept"] > 0) else "ERR"
        lines.append(f"[{mark}] {r['name']}")
        lines.append(f"      주소: {r['url']}")
        lines.append(f"      후보 {r['candidates']} -> 추출 {r['found']} -> 사용 {r['kept']}")
        lines.append(f"      진단: {advise(r)}")
    lines += ["", "-" * 60, "[제외된 항목 샘플]"]
    for t, why, src in dropped[:40]:
        lines.append(f"  - ({why}) {t[:50]}  <{src}>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[*] 진단 리포트 저장: {path}")


# ======================================================== 4. Supabase 전송
def sync_to_supabase(event_data, sb_url, sb_key, ctx):
    prizes = [{"n": r.get("item_name", "경품"), "q": r.get("winners_count", 1), "u": r.get("unit_price", 0)}
              for r in event_data.get("rewards", [])]
    payload = {
        "owner_id": OWNER_ID, "title": event_data["title"], "tpl": "경품 응모",
        "target_region": event_data.get("target_region", "경기도"),
        "target_ages": event_data.get("target_age", ["ALL"]),
        "start_date": event_data["period"]["start"] or None, "end_date": event_data["period"]["end"] or None,
        "prizes": prizes, "link": event_data.get("apply_url") or event_data.get("source_url"),
        "budget": sum((p["q"] or 0) * (p["u"] or 0) for p in prizes), "status": "live",
        "org_name": event_data.get("org_name", "공공기관"), "poster_url": event_data.get("poster_image_url", ""),
        "source_url": event_data.get("source_url", ""), "shield_rule": event_data.get("abuse_prevention_rule", ""),
    }
    req = urllib.request.Request(f"{sb_url}/rest/v1/events", data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"apikey": sb_key, "Authorization": f"Bearer {sb_key}",
                                          "Content-Type": "application/json", "Prefer": "return=representation"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read().decode("utf-8", errors="ignore")}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description=f"K-Gift Hunter v{VERSION} - 경기지역 시민참여 이벤트 자동 수집")
    ap.add_argument("--sources", default=DEFAULT_SOURCES, help="수집 대상 파일 (기본: sources_gyeonggi.json)")
    ap.add_argument("--only", help="이름에 이 글자가 들어간 대상만 수집 (예: --only 수원)")
    ap.add_argument("--no-discover", action="store_true", help="시청 첫 화면 자동 탐색(homepages) 건너뛰기")
    ap.add_argument("--list-url", help="목록 페이지 URL 하나만 수집")
    ap.add_argument("--url", help="이벤트 상세 페이지 URL 하나만 추출")
    ap.add_argument("--html-file", help="저장해 둔 상세 HTML 파일로 추출 테스트")
    ap.add_argument("--org", default="", help="기관명 직접 지정 (예: 수원시)")
    ap.add_argument("--accept-all", action="store_true", help="--list-url 이 행사/이벤트 전용 게시판이면 모든 게시글을 후보로")
    ap.add_argument("--out", default="events.json")
    ap.add_argument("--report", default="hunter_report.txt")
    ap.add_argument("--time-budget", type=int, default=0, help="전체 제한 시간(초). 넘으면 중단하고 그때까지 결과 저장 (0=무제한)")
    ap.add_argument("--max", type=int, default=8, help="목록 하나당 최대 상세 수집 개수")
    ap.add_argument("--min-score", type=int, default=50, help="이 점수 미만은 제외 (기본 50)")
    ap.add_argument("--keep-ended", action="store_true", help="마감된 이벤트도 포함")
    ap.add_argument("--allow-no-date", action="store_true", help="기간을 못 찾은 글도 포함")
    ap.add_argument("--no-sync", action="store_true", help="Supabase 전송 없이 JSON만 저장")
    ap.add_argument("--ignore-robots", action="store_true", help="robots.txt 무시 (권장하지 않음)")
    ap.add_argument("--insecure", action="store_true", help="SSL 인증서 검증 끄기")
    args = ap.parse_args()

    today = dt.date.today()
    net = Net(insecure=args.insecure, delay=0.7, respect_robots=not args.ignore_robots)
    print(f"[*] K-Gift Hunter v{VERSION} 가동 (오늘: {today})")
    results, rows, targets = [], [], []
    cache_path = os.path.join(HERE, "discovered_boards.json")
    cache = load_json(cache_path, {})

    if args.html_file:
        with open(args.html_file, "rb") as f:
            html = decode_html(f.read())
        results.append(extract_event(html, args.url or "file://" + os.path.abspath(args.html_file), args.org, today))
    elif args.url:
        try:
            results.append(extract_event(net.get(args.url), args.url, args.org, today))
        except Exception as e:
            print(f"[-] 수집 실패: {e}")
            sys.exit(1)
    else:
        homepages = []
        if args.list_url:
            targets = [{"name": args.org or args.list_url, "org": args.org, "list_url": args.list_url, "accept_all": args.accept_all}]
        else:
            if not os.path.exists(args.sources):
                print(f"[-] 수집 대상 파일이 없습니다: {args.sources}")
                sys.exit(1)
            targets, homepages = load_sources(args.sources)
        if args.only:
            targets = [t for t in targets if args.only in t["name"]]
            homepages = [h for h in homepages if args.only in h["name"]]
        # 시청 첫 화면 -> 이벤트/행사 게시판 자동 탐색 (한 번 성공한 게시판은 캐시에 기억)
        if not args.no_discover:
            td0 = time.time()
            for h in homepages:
                if args.time_budget and time.time() - td0 > args.time_budget * 0.4:
                    print("[!] 첫 화면 탐색 시간 초과: 나머지 시군은 다음 실행에서 탐색합니다.")
                    break
                boards = cache.get(h["url"])
                if boards:
                    print(f"[*] {h['name']}: 기억해 둔 게시판 {len(boards)}개 사용")
                else:
                    try:
                        print(f"[*] {h['name']}: 첫 화면 탐색 중...", flush=True)
                        boards = discover_boards(net, h["url"])
                        print(f"[*] {h['name']}: 메뉴에서 게시판 {len(boards)}개 자동 발견")
                    except Exception as e:
                        rows.append({"name": h["name"] + " (첫 화면)", "url": h["url"], "error": str(e),
                                     "candidates": 0, "found": 0, "kept": 0, "reasons": Counter()})
                        print(f"[-] {h['name']}: 첫 화면 접속 실패 ({str(e)[:50]})")
                        continue
                for b in boards:
                    if any(t["list_url"] == b["url"] for t in targets):
                        continue  # 이미 수집 대상에 있는 게시판은 중복 수집하지 않음
                    targets.append({"name": f"{h['name']} · {b['text']}", "org": h.get("org", ""), "list_url": b["url"],
                                    "accept_all": True, "_home": h["url"], "_text": b["text"]})
        t0 = time.time()
        for i, t in enumerate(targets, 1):
            if args.time_budget and time.time() - t0 > args.time_budget:
                print(f"[!] 제한 시간({args.time_budget}초) 초과: 남은 {len(targets) - i + 1}개 대상은 건너뜁니다.")
                for rest in targets[i - 1:]:
                    rows.append({"name": rest["name"], "url": rest["list_url"], "error": "시간 초과로 건너뜀",
                                 "candidates": 0, "found": 0, "kept": 0, "reasons": Counter()})
                break
            print(f"[{i}/{len(targets)}] {t['name']}  <- {t['list_url']}", flush=True)
            got, log, st, lh = smart_collect(net, t, args.max, today)
            print("\n".join(log))
            for r in got:
                r["_source"] = t["name"]
            results += got
            row = {"name": t["name"], "url": t["list_url"], "error": st["error"], "candidates": st["candidates"],
                   "found": len(got), "kept": 0, "reasons": Counter()}
            if not st["error"] and st["candidates"] == 0:
                row["debug"] = save_debug(t["name"], lh)
            rows.append(row)

    if args.keep_ended or args.allow_no_date:
        for r in results:
            if (args.keep_ended and r["skip_reason"] == "마감됨") or (args.allow_no_date and r["skip_reason"] == "기간 확인 불가"):
                r["skip_reason"] = ""
    kept, dropped = filter_and_dedup(results, args.min_score)

    # 소스별 집계 + 진단 자료 저장 + 학습(캐시) 갱신
    kept_by = Counter(r.get("_source") for r in kept)
    for row in rows:
        row["kept"] = kept_by.get(row["name"], 0)
        for _, why, src in dropped:
            if src == row["name"]:
                row["reasons"][why] += 1
        if row["found"] > 0 and row["kept"] == 0 and "debug" not in row:
            sample = next((r for r in results if r.get("_source") == row["name"]), None)
            if sample:
                row["debug"] = save_debug(row["name"], sample.get("_html", ""), "detail")
    if not (args.html_file or args.url):
        by_home = {}
        for t in targets:
            if t.get("_home"):
                by_home.setdefault(t["_home"], []).append(t)
        changed = False
        for home, ts in by_home.items():
            good = [{"text": t["_text"], "url": t["list_url"]} for t in ts if kept_by.get(t["name"], 0) > 0]
            if good and cache.get(home) != good:
                cache[home], changed = good, True
            elif not good and home in cache:
                cache.pop(home)  # 더 이상 안 통하면 잊고 다음엔 다시 탐색
                changed = True
        if changed:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"\n[*] 수집 {len(results)}건 -> 사용 {len(kept)}건 / 제외 {len(dropped)}건")
    for r in kept:
        d = r["event_data"]
        print(f"    + [{r['confidence_score']}점·{d['category']}] {d['title'][:38]} | {d['period']['start']}~{d['period']['end']} | {d['target_region']}")
    if rows:
        print("\n[*] 사이트별 진단")
        for row in rows:
            print(f"    {'OK ' if (row['kept'] or set(row['reasons']) == {'중복'}) else 'ERR'} {row['name'][:30]:30s} 후보{row['candidates']:>3} -> 사용{row['kept']:>3} | {advise(row)[:60]}")
        write_report(args.report if os.path.isabs(args.report) else os.path.join(HERE, args.report), rows, kept, dropped)

    out_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    save_json(kept, out_path)

    if not args.no_sync and kept:
        print("\n[*] Supabase 전송 시도...")
        ctx = ssl.create_default_context()
        for r in kept:
            res = sync_to_supabase(r["event_data"], DEFAULT_SB_URL, DEFAULT_SB_KEY, ctx)
            tag = "[+] 성공" if res["ok"] else f"[-] 실패 HTTP {res['status']}"
            print(f"    {tag}: {r['event_data']['title'][:35]}")
            if not res["ok"] and res["status"] == 401:
                print("    -> RLS 때문에 쓰기가 막혀 있습니다. SQL(권한 설정)을 먼저 실행하세요.")
                break
    # 진단 자료(리포트 + debug 폴더)를 zip 하나로 묶기 -> 문제 시 이 파일 하나만 전달하면 됨
    dbg = os.path.join(HERE, "debug")
    rep_path = args.report if os.path.isabs(args.report) else os.path.join(HERE, args.report)
    if rows and (os.path.isdir(dbg) or os.path.exists(rep_path)):
        zp = os.path.join(HERE, "hunter_debug.zip")
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
            if os.path.exists(rep_path):
                z.write(rep_path, os.path.basename(rep_path))
            if os.path.isdir(dbg):
                for fn in os.listdir(dbg):
                    z.write(os.path.join(dbg, fn), os.path.join("debug", fn))
        print(f"[*] 진단 자료 묶음: {zp}  <- 문제가 있으면 이 파일 하나만 보내 주세요")
    print("\n[+] 완료!")


if __name__ == "__main__":
    main()
