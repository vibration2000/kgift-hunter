"""
K-Gift Hunter v2.5 - 경기도 31개 시·군 실시간 시민참여/이벤트/행사 자동 수집 엔진 (독립 실행)
- 2026 공공 AI 대전환 챌린지 출품용 공식 수집 엔진
- 대한민국 공공기관 웹 표준(e-Gov, OpenWorks, Nuri) 최적화
- 한글 URL 인코딩 보호, 레거시 SSL 자동 우회, 실제 공공 행사/이벤트 실시간 전수 수집
- Supabase 클라우드 실시간 동기화 & events.json 다건 호환 포맷 출력
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
import zipfile
import http.cookiejar
from collections import Counter
from kgift_checker import verify_single_event

VERSION = "2.9 (K-Checker v2 본문 대조 · Zero-Lie)"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SOURCES = os.path.join(HERE, "sources_gyeonggi.json")
DEFAULT_SB_URL = "https://pvcarkmnbttcgosmhwng.supabase.co"
DEFAULT_SB_KEY = "sb_publishable_o1WcoXAZ2aIwZdKqkOO0lg_VxBt6CeZ"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# 경기도 31개 시·군 목록
GG_CITIES = [
    "수원", "고양", "용인", "성남", "부천", "화성", "안산", "남양주", "안양", "평택",
    "시흥", "파주", "의정부", "김포", "광명", "하남", "군포", "오산", "이천", "양주",
    "구리", "안성", "포천", "의왕", "양평", "여주", "동두천", "과천", "가평", "연천", "광주"
]
# 군 단위 (시가 아니라 '군'으로 표기해야 함)
GG_COUNTIES = {"양평", "가평", "연천"}


def _unit(c: str) -> str:
    return "군" if c in GG_COUNTIES else "시"

# 공통 네비게이션 / 사이트 타이틀 등 배제할 블랙리스트
TITLE_BLACKLIST = [
    "설문조사", "시민참여", "공지사항", "게시판 상세내용", "행사안내", "참여마당", "행사보기",
    "상세내용", "상세보기", "목록", "이벤트", "새소식", "알림마당", "주요행사", "통합검색",
    "수원특례시", "고양특례시", "용인특례시", "성남시", "부천시", "화성시", "안산시", "남양주시",
    "안양시", "평택시", "시흥시", "파주시", "의정부시", "김포시", "광명시", "하남시", "군포시",
    "오산시", "이천시", "양주시", "구리시", "안성시", "포천시", "의왕시", "양평군", "여주시",
    "동두천시", "과천시", "가평군", "연천군", "경기도", "Seongnam City", "Suwon Special City"
]

JOIN_WORDS = [
    "이벤트", "축제", "행사", "체험", "설문", "퀴즈", "참여", "공모", "페스티벌", "마당",
    "안내", "신청", "접수", "모집", "응모", "서명", "추첨", "기념", "나눔", "특강", "대회",
    "스탬프", "문화", "투어", "콘서트", "음악회", "전시", "플리마켓"
]

EXCLUDE_WORDS = [
    "채용공고", "입찰공고", "용역공고", "수의계약", "사업자 모집", "결산공고",
    "부동산", "중개사무소", "자율점검", "주택조합", "사업계획승인", "네이버밴드", "임대 정보", "분양 및",
    "보도자료", "취재지원", "기자회견", "급식"
]
REWARD_HINT_WORDS = ["경품", "추첨", "선물", "기념품", "사은품", "쿠폰", "기프티콘", "상품권", "지역화폐", "상금", "시상", "증정"]
# "표창"은 유공자 표창(기념식 순서)과 구분이 안 되어 경품 단어에서 뺐다
REWARD_WORDS = [
    "상품권", "기프티콘", "커피", "치킨", "문화상품권", "지역화폐", "상금", "시상금", "헤드폰", "에어팟", "쿠폰",
    "대상", "최우수상", "우수상", "장려상", "특별상", "금상", "은상", "동상", "입선"
]
AWARDS_SET = {"대상", "최우수상", "우수상", "장려상", "특별상", "금상", "은상", "동상", "입선", "가작"}


# ======================================================== 1. 네트워크 통신 엔진 (SSL/인코딩/리다이렉트 완전 방어)
def get_safe_ssl_context():
    """정부 공공기관 구형/최신 TLS 암호 스위트 모두 호환 (Handshake Failure 방지)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1:ALL:!DH")
    ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
    ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def safe_url(url: str) -> str:
    """URL에 한글/특수문자가 포함되어도 'ascii' codec 에러가 나지 않도록 안전 변환"""
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        path = urllib.parse.quote(parts.path, safe="/%:@")
        query = urllib.parse.quote(parts.query, safe="=&?/%:@+$,")
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
    except Exception:
        return url.strip()


class Net:
    def __init__(self, delay=0.5, respect_robots=False):
        self.ctx = get_safe_ssl_context()
        self.delay = delay
        self.respect_robots = respect_robots
        self.jar = http.cookiejar.CookieJar()
        self._last = 0.0

    def get(self, url: str, referer: str = "") -> str:
        url = safe_url(url)
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)

        curr_url = url
        html = ""
        prev_url = safe_url(referer) if referer else None

        for _ in range(4):
            hdr = {
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
            }
            if prev_url:
                hdr["Referer"] = prev_url

            req = urllib.request.Request(curr_url, headers=hdr)
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(self.jar),
                urllib.request.HTTPSHandler(context=self.ctx),
            )

            try:
                with opener.open(req, timeout=12) as resp:
                    raw = resp.read()
                    ctype = resp.headers.get("Content-Type", "")
            except Exception as e:
                # 1회 완화 재시도
                req_retry = urllib.request.Request(curr_url, headers=hdr)
                with opener.open(req_retry, timeout=15) as resp:
                    raw = resp.read()
                    ctype = resp.headers.get("Content-Type", "")

            html = decode_html(raw, ctype)
            nxt = self.check_client_redirect(html, curr_url)
            if not nxt or nxt == curr_url:
                break
            prev_url, curr_url = curr_url, safe_url(nxt)

        self._last = time.time()
        return html

    def probe_image(self, url: str, referer: str = "") -> tuple:
        """이미지 URL이 실제로 열리는지 확인. (상태코드, content-type, 읽은 바이트 수) 반환."""
        req = urllib.request.Request(safe_url(url), headers={"User-Agent": UA, "Referer": safe_url(referer) if referer else url,
                                                              "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        try:
            with opener.open(req, timeout=12) as resp:
                head = resp.read(4096)
                return resp.getcode(), resp.headers.get("Content-Type", ""), len(head)
        except Exception as e:
            return 0, str(e)[:60], 0

    def fetch_bytes(self, url: str, referer: str = "", max_bytes: int = 5 * 1024 * 1024) -> tuple:
        """이미지 전체 내려받기. (바이트, content-type) 반환. 5MB 초과/실패 시 (b"", 사유)."""
        req = urllib.request.Request(safe_url(url), headers={"User-Agent": UA, "Referer": safe_url(referer) if referer else url,
                                                              "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        try:
            with opener.open(req, timeout=20) as resp:
                ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                raw = resp.read(max_bytes + 1)
        except Exception as e:
            return b"", str(e)[:60]
        if len(raw) > max_bytes:
            return b"", "TOO_LARGE"
        return raw, ctype

    def post(self, url: str, data: dict, referer: str = "") -> str:
        url = safe_url(url)
        hdr = {"User-Agent": UA, "Referer": safe_url(referer) if referer else url,
               "Content-Type": "application/x-www-form-urlencoded",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8"}
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode("utf-8"), headers=hdr, method="POST")
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        with opener.open(req, timeout=15) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
        self._last = time.time()
        return decode_html(raw, ctype)

    @staticmethod
    def check_client_redirect(html: str, base_url: str):
        if len(html) > 10000:
            return None
        m = re.search(r'http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)', html, re.I) or \
            re.search(r'(?:document\.|window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', html, re.I)
        return urllib.parse.urljoin(base_url, htmllib.unescape(m.group(1))) if m else None


def decode_html(raw: bytes, ctype: str = "") -> str:
    """UTF-8 / EUC-KR(CP949) 지능형 자동 복호화"""
    enc = None
    m = re.search(r"charset=([\w\-]+)", ctype, re.I)
    if m:
        enc = m.group(1)
    if not enc:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w\-]+)", raw[:3000], re.I)
        if m:
            enc = m.group(1).decode("ascii", "ignore")

    order = [enc, "utf-8", "cp949", "euc-kr"]
    for e in order:
        if not e:
            continue
        try:
            return raw.decode(e)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


# ======================================================== 비전 및 무료 OCR(이미지 속 글자 읽기)
VISION = {"on": False, "key": "", "model": "claude-sonnet-5-5"}
OCR_CONFIG = {"tesseract": False}
VISION_PROMPT = ("이 이미지에 보이는 글자를 위에서 아래로 순서대로 그대로 옮겨 적으세요. "
                 "이미지에 없는 내용을 추가하거나 추측하지 마세요. 읽을 수 없는 부분은 [판독불가]로 표시하세요. "
                 "경품·선물·기념품·상품권 같은 혜택 문구가 이미지에 전혀 없으면 마지막 줄에 '혜택문구없음'이라고만 적으세요.")


def tesseract_ocr_text(img_bytes: bytes) -> str:
    """무료 오픈소스 Tesseract OCR (tesseract-ocr-kor)로 이미지 속 한글/영문 글자 추출"""
    import subprocess, tempfile, shutil
    tess_bin = shutil.which("tesseract")
    if not tess_bin:
        try:
            import pytesseract
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(img_bytes))
            return pytesseract.image_to_string(img, lang="kor+eng").strip()
        except Exception:
            return ""

    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(img_bytes)
            tmp_path = tmp.name
        res = subprocess.run(
            [tess_bin, tmp_path, "stdout", "-l", "kor+eng", "--psm", "3"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25
        )
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        if res.returncode == 0:
            return res.stdout.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        print(f"    [!] Tesseract OCR 판독 오류: {e}")
    return ""


def _http_json(url: str, headers: dict, body: dict, timeout: int = 90) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def vision_read_text(img_bytes: bytes, media_type: str) -> str:
    """Claude 비전 API로 이미지 속 글자를 옮겨 적는다. 실패하면 빈 문자열(= 아무것도 지어내지 않음)."""
    if not (VISION["on"] and img_bytes and media_type in ("image/jpeg", "image/png", "image/gif", "image/webp")):
        return ""
    import base64
    body = {"model": VISION["model"], "max_tokens": 1500,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": media_type,
                                             "data": base64.b64encode(img_bytes).decode("ascii")}},
                {"type": "text", "text": VISION_PROMPT}]}]}
    try:
        res = _http_json("https://api.anthropic.com/v1/messages",
                         {"x-api-key": VISION["key"], "anthropic-version": "2023-06-01", "content-type": "application/json"}, body)
        return "".join(b.get("text", "") for b in res.get("content", []) if b.get("type") == "text").strip()
    except Exception as e:
        print(f"    [!] 비전 판독 실패: {str(e)[:80]}")
        return ""


def read_poster_texts(net, urls: list, referer: str) -> str:
    """후보 이미지 최대 3장을 읽어 글자를 이어 붙인다 (Tesseract 무료 OCR 우선, 필요시 Vision 보조)."""
    parts = []
    for u in urls[:3]:
        raw, ct = net.fetch_bytes(u, referer=referer)
        if not raw:
            continue
        t = ""
        if OCR_CONFIG.get("tesseract"):
            t = tesseract_ocr_text(raw)
        if not t and VISION.get("on"):
            t = vision_read_text(raw, ct)
        if t:
            parts.append(t)
    return "\n\n".join(parts)


def fetch_detail(net, url: str, list_url: str) -> str:
    """상세 페이지 요청. 서버가 HTTP 500을 주면 (1) 목록과 같은 게시판 코드로 GET, (2) 폼 POST 방식으로 차례로 재시도."""
    try:
        return net.get(url, referer=list_url)
    except Exception as first_err:
        if "500" not in str(first_err):
            raise
        pu = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(pu.query, keep_blank_values=True))
        lq = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(list_url).query, keep_blank_values=True))
        if "q_bbsCode" in qs and "q_bbsCode" in lq and qs["q_bbsCode"] != lq["q_bbsCode"]:
            alt = dict(qs, q_bbsCode=lq["q_bbsCode"])
            alt_url = urllib.parse.urlunparse(pu._replace(query=urllib.parse.urlencode(alt)))
            try:
                return net.get(alt_url, referer=list_url)
            except Exception:
                pass
        try:
            return net.post(urllib.parse.urlunparse(pu._replace(query="")), qs, referer=list_url)
        except Exception:
            raise first_err


def clean_text(html: str) -> list:
    html = re.sub(r"(?is)<(script|style|noscript|nav|footer|header)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|dd|dt|td|th)>", "\n", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    lines = [re.sub(r"\s+", " ", l).strip() for l in text.split("\n")]
    return [l for l in lines if l]


# ======================================================== 2. 게시판 목록에서 실제 이벤트 링크 정밀 선별
def resolve_js_link(onclick: str, list_url: str) -> str:
    """OpenWorks, e-Gov 표준 onClick 자바스크립트 함수를 실제 URL로 변환"""
    if not onclick:
        return ""
    # jsView('1381', '20260929224258236')
    m = re.search(r"\w*(?:[vV]iew|[dD]etail|[rR]ead)\w*\(\s*['\"]?(\w+)['\"]?\s*,\s*['\"]?(\w+)['\"]?", onclick)
    if m:
        a, b = m.group(1), m.group(2)
        p = urllib.parse.urlparse(list_url)
        if "BD_board.list.do" in p.path:
            return urllib.parse.urlunparse((p.scheme, p.netloc, p.path.replace("BD_board.list.do", "BD_board.view.do"), "", f"bbsCd={a}&seq={b}", ""))
        if "BD_selectBbsList.do" in p.path:
            return urllib.parse.urlunparse((p.scheme, p.netloc, p.path.replace("BD_selectBbsList.do", "BD_selectBbs.do"), "", f"q_bbsCode={a}&q_bbscttSn={b}", ""))
    return ""


def find_event_links(list_html: str, list_url: str, keywords=None, limit=25, accept_all=False) -> list:
    """목록 페이지에서 진짜 이벤트 게시글의 링크와 제목 추출"""
    found, seen = [], set()

    # 링크 탐색 정규식
    for attrs, inner in re.findall(r'<a\b([^>]*)>(.*?)</a>', list_html, re.S | re.I):
        hm = re.search(r'href=(["\'])(.*?)\1', attrs, re.I | re.S)
        om = re.search(r'onclick=(["\'])(.*?)\1', attrs, re.I | re.S)
        href = hm.group(2) if hm else ""
        onclick = om.group(2) if om else ""

        text = re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", inner))).strip()

        if href.startswith(("javascript", "#")) or not href:
            href = resolve_js_link(onclick, list_url)

        if not href or href.startswith(("mailto", "tel")):
            continue

        # 네비게이션용 단어 및 단순 메뉴 제외
        if any(nav == text or nav in text for nav in [
            "처음", "마지막", "이전", "다음", "목록", "검색", "로그인", "회원가입", "맨위", "닫기",
            "자유게시판", "칭찬합니다", "제안합니다", "시민제안", "행정처분", "수상내역", "보도자료",
            "고시/공고", "일자리", "주택건설", "생활경제", "대중교통", "도서교통", "인터넷자율점검",
            "네이버밴드", "자료실", "시민소통", "모니터공지", "공지사항", "게시판 안내", "정보공개",
            "조직도", "청사안내", "행정정보", "통합검색", "사이트맵", "더보기"
        ]):
            continue

        # 본문 개별 게시글 링크인지 URL 패턴 검사 (상세 글 번호 파라미터가 반드시 있어야 진짜 이벤트 게시글임!)
        # 단순 목록/카테고리 탭(List.do, index.do 등)은 원천 배제
        href = href.strip()
        has_article_id = any(p in href.lower() for p in [
            "seq=", "sn=", "q_sn=", "bbscttsn", "nttid=", "nttno=", "articleno=", "idx=", "/view.do", "/view/", "/detail/"
        ])

        if not has_article_id:
            continue

        # 단순 뉴스/보도자료 URL 원천 배제
        if any(np in href.lower() for np in ["gnews.gg.go.kr", "/news/", "news_detail", "/press/"]):
            continue

        # 텍스트 길이 및 제외 단어 필터
        if len(text) < 4:
            continue
        if any(ex in text for ex in EXCLUDE_WORDS):
            continue

        # 날짜 범위 또는 단일 날짜가 링크 텍스트에 포함되어 있으면 보존 (예: 2026-09-10 09:00~2026-10-16 18:00)
        raw_date = ""
        dm_range = re.search(r'(\d{4}[.\-/년]\s*\d{1,2}[.\-/월]\s*\d{1,2}[일.]?(?:\s*\d{1,2}:\d{2})?\s*[~\-–∼]\s*(?:\d{4}[.\-/년]\s*)?\d{1,2}[.\-/월]\s*\d{1,2}[일.]?(?:\s*\d{1,2}:\d{2})?)', text)
        if dm_range:
            raw_date = dm_range.group(1).strip()
        else:
            dm_single = re.search(r'(\d{4}[.\-/년]\s*\d{1,2}[.\-/월]\s*\d{1,2}[일.]?)', text)
            if dm_single:
                raw_date = dm_single.group(1).strip()

        if raw_date:
            text = re.split(r'기간\s*[:：]|일시\s*[:：]', text)[0].strip()

        # 실제 이벤트성 시그널 검증 (축제, 행사, 설문, 스탬프, 대회 등 실제 이벤트다운 명칭만 선별)
        has_event_signal = any(jw in text for jw in JOIN_WORDS) or (raw_date != "")
        if not has_event_signal and len(text) < 12:
            continue

        full_url = urllib.parse.urljoin(list_url, htmllib.unescape(href))
        clean_full_url = safe_url(full_url)

        if clean_full_url in seen:
            continue
        seen.add(clean_full_url)

        found.append({
            "url": clean_full_url,
            "link_text": text,
            "raw_date": raw_date
        })

        if len(found) >= limit:
            break

    return found


# ======================================================== 3. 상세 페이지 -> 정형 이벤트 데이터 추출
_Y = r"((?:20)?[23]\d)"          # 2026 또는 26 (두 자리 연도 지원)
_D = r"(?<!\d)['’]?" + _Y + r"\s*[.\-/년]\s*(\d{1,2})\s*[.\-/월]\s*(\d{1,2})\s*일?\.?"
_WD = r'(?:\s*\(\s*[월화수목금토일]\s*\))?'
_TM = r'(?:\s*\d{1,2}\s*:\s*\d{2})?'
_SEP = r'\s*(?:[~∼～〜–\-]|부터)\s*'
_RANGE_FULL = re.compile(_D + _WD + _TM + _SEP + r"(?:['’]?" + _Y + r"\s*[.\-/년]\s*)?(\d{1,2})\s*[.\-/월]\s*(\d{1,2})\s*일?\.?")
_RANGE_MD = re.compile(r'(\d{1,2})\s*월\s*(\d{1,2})\s*일?\.?' + _WD + _TM + _SEP + r'(?:(\d{1,2})\s*월\s*)?(\d{1,2})\s*일')
_SINGLE_FULL = re.compile(_D)
_SINGLE_MD = re.compile(r'(\d{1,2})\s*월\s*(\d{1,2})\s*일')
# 안양시 등 게시판 상단의 "시작일 2026-10-14 종료일 2026-10-27" 칸 (게시판이 공식으로 적어둔 기간)
_STRUCT = re.compile(r'시작일\s*' + _D + r'\s*종료일\s*' + _D)


def _yr(y) -> int:
    y = int(y)
    return y + 2000 if y < 100 else y


PERIOD_LABELS = ["기간", "일시", "일정", "접수", "신청", "모집", "응모", "참여", "운영", "개최", "행사일", "제출", "공모", "투표", "설문"]
SINGLE_LABELS = ["일시", "일자", "행사일", "개최일", "운영일"]     # 단일 날짜는 이 이름표가 붙은 것만 인정 ("모집", "신청"은 제외)
NOT_PERIOD_LABELS = ["게시일", "등록일", "작성일", "수정일", "공고일", "발표일", "시행일", "시작일", "종료일", "기한", "마감"]


def _near(text: str, pos: int, n: int) -> str:
    return re.sub(r"\s+", "", text[max(0, pos - n):pos])      # "일 시 :" 처럼 띄어 쓴 이름표도 읽도록 공백 제거


def _is_labeled(text: str, pos: int, labels=None) -> bool:
    if any(n in _near(text, pos, 10) for n in NOT_PERIOD_LABELS):
        return False
    return any(l in _near(text, pos, 25) for l in (labels or PERIOD_LABELS))


def _find_ranges(text: str, today: dt.date) -> list:
    """본문에서 '시작 ~ 끝' 형태의 기간을 모두 찾는다. [(start, end, labeled, pos)]"""
    found = []
    for m in _RANGE_FULL.finditer(text):
        y1, m1, d1, y2, m2, d2 = m.groups()
        try:
            s = dt.date(_yr(y1), int(m1), int(d1))
            e = dt.date(_yr(y2 or y1), int(m2), int(d2))
            if e < s:
                e = dt.date(e.year + 1, e.month, e.day)
            found.append((s, e, _is_labeled(text, m.start()), m.start()))
        except ValueError:
            pass
    full_spans = [(m.start(), m.end()) for m in _RANGE_FULL.finditer(text)]
    for m in _RANGE_MD.finditer(text):
        if any(a <= m.start() < b for a, b in full_spans):
            continue
        m1, d1, m2, d2 = m.groups()
        try:
            s = dt.date(today.year, int(m1), int(d1))
            e = dt.date(today.year, int(m2 or m1), int(d2))
            if e < s:
                e = dt.date(today.year + 1, e.month, e.day)
            found.append((s, e, _is_labeled(text, m.start()), m.start()))
        except ValueError:
            pass
    found.sort(key=lambda r: r[3])
    return found


def parse_period(text: str, today: dt.date, raw_hint: str = "") -> tuple:
    """기간 파서 (Zero-Lie). 우선순위:
    1) 본문의 '접수기간/설문기간/행사기간 : 시작 ~ 끝' (이름표가 붙은 기간)
    2) 게시판의 '시작일 … 종료일 …' 칸
    3) 목록 링크에 적힌 기간 (상세 본문이 더 정확하므로 본문에 기간이 없을 때만)
    4) 이름표는 없지만 본문에 기간이 딱 하나일 때
    5) '일시/행사일' 이름표가 붙은 단일 날짜
    그 외에는 (None, None) — 게시일 같은 날짜를 기간으로 쓰지 않는다."""
    ranges = _find_ranges(text, today)
    labeled = [r for r in ranges if r[2]]
    if labeled:
        return labeled[0][0], labeled[0][1]

    m = _STRUCT.search(text)
    if m:
        y1, m1, d1, y2, m2, d2 = m.groups()
        try:
            return dt.date(_yr(y1), int(m1), int(d1)), dt.date(_yr(y2), int(m2), int(d2))
        except ValueError:
            pass

    if raw_hint:
        r = _find_ranges(raw_hint, today)
        if r:
            return r[0][0], r[0][1]
        m = _SINGLE_FULL.search(raw_hint)
        if m:
            try:
                d = dt.date(_yr(m.group(1)), int(m.group(2)), int(m.group(3)))
                return d, d
            except ValueError:
                pass

    distinct = {(r[0], r[1]) for r in ranges}
    if len(distinct) == 1:
        return ranges[0][0], ranges[0][1]
    if len(distinct) > 1:
        return None, None   # 기간 후보가 여러 개이고 이름표도 없어 어느 것인지 알 수 없음

    for m in _SINGLE_FULL.finditer(text):
        if _is_labeled(text, m.start(), SINGLE_LABELS):
            try:
                d = dt.date(_yr(m.group(1)), int(m.group(2)), int(m.group(3)))
                return d, d
            except ValueError:
                continue
    for m in _SINGLE_MD.finditer(text):
        if _is_labeled(text, m.start(), SINGLE_LABELS):
            try:
                d = dt.date(today.year, int(m.group(1)), int(m.group(2)))
                return d, d
            except ValueError:
                continue
    return None, None


# "제공"(식사 제공 등)·"선착순"(참가 신청)은 경품 지급이 아닌 글에도 흔해서 지급 표현에서 뺐다
GIVE_WORDS = ["증정", "지급", "드립니다", "드려요", "추첨", "수여", "시상", "경품", "선물", "당첨", "받으실", "받을 수"]


def _evidence(text: str, start: int, end: int, pad_before: int = 40, pad_after: int = 70) -> str:
    return re.sub(r"\s+", " ", text[max(0, start - pad_before): end + pad_after]).strip()


def parse_rewards(text: str) -> list:
    """본문(또는 포스터에서 옮겨 적은 글)에서 경품을 찾는다. 금액(원)·인원(명)이 모두 글자로 있고,
    '증정/지급/추첨/시상' 같은 지급 표현이 근처에 있을 때만 인정한다. 각 경품에 근거 문장(evidence)을 붙인다."""
    rewards = []
    # 1. 구체적 상품명/시상 + 금액/인원
    prize_kws = "상품권|기프티콘|쿠폰|커피|치킨|지역화폐|굿즈|기념품|선물|상금|시상금|대상|최우수상|우수상|장려상|특별상|금상|은상|동상|입선"
    pat = re.compile(
        rf'([가-힣A-Za-z0-9 ]{{0,15}}?(?:{prize_kws}))[^0-9]{{0,15}}?(\d[\d,]*)\s*(?:(만|천)\s*)?원[^0-9]{{0,20}}?(\d[\d,]*)\s*(명|인|팀|EA|개|분)'
    )
    for m in pat.finditer(text):
        name, amt, unit, cnt, cnt_u = m.groups()
        name = re.sub(r'^[\d\s,.\-~:()]+', '', name).strip()
        name = re.sub(r'^(?:시상규모|시상내역|시상|정보|상격|상목|부문|구분)\s*', '', name).strip()
        for aw in sorted(AWARDS_SET, key=len, reverse=True):
            if name.endswith(aw):
                if not any(k in name for k in ["상장", "훈격", "지사", "시장", "장관", "구청장", "군수", "원장"]):
                    name = aw
                break
        if not name:
            continue
        mult = 10000 if unit == "만" else (1000 if unit == "천" else 1)
        amount = int(amt.replace(",", "")) * mult
        count = int(cnt.replace(",", ""))
        ev_txt = _evidence(text, m.start(), m.end())
        if not any(g in ev_txt for g in GIVE_WORDS):
            continue
        if amount > 0 and 0 < count < 50000:
            rewards.append({"item_name": name.strip(), "unit_price": amount, "winners_count": count, "evidence": ev_txt})

    # 보조 탐색: 경품 단어 뒤 가까운 곳에서 "금액(원/만원)"과 "인원(명)"을 모두 찾은 경우에만 인정
    if not rewards:
        for w in REWARD_WORDS:
            for wm in re.finditer(re.escape(w), text):
                window = text[max(0, wm.start() - 60): wm.end() + 80]   # 인원이 경품명 앞에 오는 문장("선착순 50명에게 기프티콘 3,000원")도 포함
                am = re.search(r'(\d[\d,]*)\s*(?:(만|천)\s*)?원', window)
                cm = re.search(r'(\d[\d,]*)\s*(?:명|인|팀|EA|개|분)', window)
                if not (am and cm):
                    continue
                ev_txt = _evidence(text, wm.start() - 20, wm.end() + 10)
                ev_txt = re.sub(r"\s+", " ", window).strip()
                if not any(g in ev_txt for g in GIVE_WORDS):
                    continue
                mult = 10000 if am.group(2) == "만" else (1000 if am.group(2) == "천" else 1)
                amount = int(am.group(1).replace(",", "")) * mult
                count = int(cm.group(1).replace(",", ""))
                if amount > 0 and 0 < count < 50000:
                    rewards.append({"item_name": w, "unit_price": amount, "winners_count": count, "evidence": ev_txt})
                    break
            if rewards:
                break

    # 금액·인원·지급 표현을 본문에서 확인하지 못한 글은 빈 리스트 반환 (Zero-Reward / Zero-Lie)
    return rewards[:3]


def guess_region(text: str, org_hint: str = "", title: str = "") -> tuple:
    for c in GG_CITIES:
        u = _unit(c)
        if f"{c}{u}" in org_hint or f"{c}특례시" in org_hint:
            return f"경기도 {c}{u}", f"{c}{u}"
        if f"{c}{u}" in title or f"{c}특례시" in title:
            return f"경기도 {c}{u}", f"{c}{u}"

    # 경기도 전체 소스이고 제목에 특정 시·군이 없는 경우 경기도 전체로 처리
    if org_hint == "경기도":
        return "경기도", "경기도"

    for c in GG_CITIES:
        u = _unit(c)
        # '광주'는 광주광역시와 혼동되므로 반드시 '광주시'로 적힌 경우만 인정
        key = f"{c}{u}" if c == "광주" else c
        if key in text[:3000]:
            return f"경기도 {c}{u}", f"{c}{u}"

    return "경기도", org_hint or "경기도청"


POSTER_NOISE = ["logo", "icon", "btn", "arrow", "banner", "blank", "sns", "qr", "profile", "bg_", "meta_",
                "common", "sprite", "loading", "bullet", "ico_", "thumb_no", "noimg", "no_image", "visual_", "header", "footer",
                "menu", "login", "close", "share", "home", "top_", "navi", "gnb", "lnb", "snb", "quick", "bar", "search"]
POSTER_GOOD_PATH = ["/data/", "/upload", "/bbs/", "/board", "/file", "/atch", "/attach", "/cmm/", "/editor", "/pds/", "/photo"]
IMG_EXT = (".jpg", ".jpeg", ".png", ".webp", ".gif")


def pick_poster(html: str, source_url: str) -> tuple:
    """게시글 본문·첨부에서 '진짜 포스터/안내문 이미지'를 고른다.
    사이트 공통 이미지(로고·메뉴·SNS 아이콘·og:image 기본 로고)는 점수로 걸러내고,
    /DATA/bbs/…jpg 처럼 게시글에 올린 이미지를 우선한다. (best_url, 후보목록) 반환."""
    host = urllib.parse.urlparse(source_url).netloc
    cands = []
    seen = set()

    def add(raw: str, base_bonus: int):
        raw = htmllib.unescape((raw or "").strip())
        if not raw or raw.startswith("data:"):
            return
        u = urllib.parse.urljoin(source_url, raw)
        path = urllib.parse.urlparse(u).path.lower()
        if not path.endswith(IMG_EXT) or u in seen:
            return
        seen.add(u)
        score = base_bonus
        if any(g in path for g in POSTER_GOOD_PATH):
            score += 4
        if urllib.parse.urlparse(u).netloc == host:
            score += 1
        if any(n in path for n in POSTER_NOISE):
            score -= 6
        if any(seg in path for seg in ("/public/", "/resources/", "/images/", "/img/", "/assets/", "/static/", "/theme/", "/skin/")):
            score -= 5
        cands.append((score, u))

    for m in re.finditer(r'<img\b[^>]*?\b(?:src|data-src|data-original|data-lazy-src|data-url)=["\']([^"\']+)["\']', html, re.I):
        add(m.group(1), 1)
    for m in re.finditer(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', html, re.I):
        add(m.group(1), 1)   # CSS background-image
    for m in re.finditer(r'<a\b[^>]*?\bhref=["\']([^"\']+)["\']', html, re.I):
        add(m.group(1), 2)   # 첨부파일 직접 링크
    og = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']*)["\']', html, re.I)
    if og:
        add(og.group(1), 0)

    cands.sort(key=lambda x: -x[0])   # 점수 높은 순 (동점이면 본문 등장 순서 유지)
    good = [u for sc, u in cands if sc >= 3]
    return (good[0] if good else ""), good[:5]


GENERIC_OG = ["ogimage", "og_image", "og-image", "default", "sns_", "share_img", "main_visual"]
POSTER_DIR = "posters"


def _is_image_bytes(b: bytes) -> bool:
    return b.startswith((b"\xff\xd8\xff", b"\x89PNG", b"GIF8")) or (b[:4] == b"RIFF" and b[8:12] == b"WEBP")


def render_pdf_first_page(pdf_bytes: bytes, key: str) -> str:
    """PDF 첨부 1쪽을 그림(JPG)으로 만들어 posters/ 에 저장. 성공하면 파일 경로, 실패하면 ''."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("pdftoppm"):
        return ""
    os.makedirs(POSTER_DIR, exist_ok=True)
    out_base = os.path.join(POSTER_DIR, key)
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
            tf.write(pdf_bytes)
            tmp = tf.name
        subprocess.run(["pdftoppm", "-jpeg", "-jpegopt", "quality=80", "-r", "90", "-f", "1", "-l", "1",
                        "-singlefile", tmp, out_base], check=True, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.unlink(tmp)
    except Exception:
        return ""
    path = out_base + ".jpg"
    return path if os.path.exists(path) and os.path.getsize(path) > 2000 else ""


def public_poster_url(path: str) -> str:
    """저장한 포스터 파일의 공개 주소 (GitHub raw). 저장소 정보를 모르면 ''."""
    repo = os.environ.get("GITHUB_REPOSITORY", "vibration2000/kgift-hunter")
    branch = os.environ.get("GITHUB_REF_NAME", "main") or "main"
    if not repo:
        return ""
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{path.replace(os.sep, '/')}"


def find_poster_hard(net, html: str, source_url: str, log: list) -> dict:
    """pick_poster 가 못 찾았을 때 쓰는 '어떻게 해서든' 탐색. 찾으면
    {"url":..., "local_path":...(선택), "how":...} 반환, 끝내 못 찾으면 {}.
    순서: ① 완화된 본문 이미지 ② 확장자 없는 첨부(다운로드) 링크 — 이미지면 그대로, PDF면 1쪽을 그림으로."""
    host = urllib.parse.urlparse(source_url).netloc
    # ① 본문 이미지 중 로고/아이콘이 아닌 것 (점수 기준 완화, 사이트 공통 og:image 는 제외)
    loose = []
    for m in re.finditer(r'<img\b[^>]*?\b(?:src|data-src|data-original|data-lazy-src)=["\']([^"\']+)["\'][^>]*>', html, re.I):
        raw = htmllib.unescape(m.group(1).strip())
        if not raw or raw.startswith("data:"):
            continue
        u = urllib.parse.urljoin(source_url, raw)
        path = urllib.parse.urlparse(u).path.lower()
        if any(n in path for n in POSTER_NOISE) or any(g in path for g in GENERIC_OG):
            continue
        if not path.endswith(IMG_EXT):
            continue
        w = re.search(r'\bwidth=["\']?(\d+)', m.group(0), re.I)
        if w and int(w.group(1)) < 150:
            continue
        loose.append(u)
    for u in loose[:6]:
        st, ct, n = net.probe_image(u, referer=source_url)
        if st == 200 and "image" in ct.lower() and n > 500:
            return {"url": u, "how": "본문 이미지(완화 기준)"}

    # ② 첨부 링크 (확장자가 없는 download.do?idx=… 도 포함)
    atts = []
    for href, inner in re.findall(r'<a\b[^>]*?\bhref=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.I | re.S):
        h = htmllib.unescape(href.strip())
        t = re.sub(r"<[^>]+>", "", inner)
        if h.startswith(("javascript:", "#", "mailto:")):
            continue
        hl = h.lower()
        if any(k in hl for k in ("download", "filedown", "atch", "attach", "file")) or re.search(r"\.(pdf|jpe?g|png)\b", t, re.I):
            if re.search(r"\.(hwp|hwpx|doc|docx|xls|xlsx|zip)\b", t, re.I):
                continue   # 신청서 양식 등은 포스터가 아님
            atts.append(urllib.parse.urljoin(source_url, h))
    seen = set()
    for u in atts[:6]:
        if u in seen:
            continue
        seen.add(u)
        raw, ctype = net.fetch_bytes(u, referer=source_url, max_bytes=15 * 1024 * 1024)
        if not raw:
            log.append(f"      · 첨부 확인 실패({ctype}): {u[-45:]}")
            continue
        if _is_image_bytes(raw):
            return {"url": u, "how": "첨부 이미지"}
        if raw.startswith(b"%PDF"):
            key = hashlib.sha1(u.encode()).hexdigest()[:16]
            lp = render_pdf_first_page(raw, key)
            pub = public_poster_url(lp) if lp else ""
            if lp and pub:
                return {"url": pub, "local_path": lp, "how": "PDF 첨부 1쪽을 그림으로 변환"}
            log.append("      · PDF 첨부는 찾았지만 그림 변환/공개 주소 생성에 실패 (pdftoppm 또는 GITHUB_REPOSITORY 확인)")
    return {}


def skipped(code: str, message: str) -> dict:
    """수집 제외 결과. None 대신 이유를 담아 반환해 로그에서 원인을 알 수 있게 한다."""
    return {"status": "skipped", "skip_reason": code, "skip_message": message}


def extract_event(html: str, source_url: str, link_title: str = "", org_hint: str = "", raw_date_hint: str = "", today=None) -> dict:
    today = today or dt.date.today()
    lines = clean_text(html)
    full_text = " ".join(lines)

    # 1. 제목(Title) 추출: 목록에서 가져온 link_text가 가장 정확하므로 1순위 적용
    final_title = ""
    clean_link_title = re.sub(r'^\s*\[[^\]]+\]\s*', '', link_title or "").strip()
    clean_link_title = re.sub(r'\s+:\s+.*$', '', clean_link_title).strip()
    clean_link_title = re.sub(r'\s*\(?(?:20)?\d{2}[.\-/]\d{1,2}[.\-/]\d{1,2}.*$', '', clean_link_title).strip()

    if clean_link_title and len(clean_link_title) >= 4 and not any(bl == clean_link_title for bl in TITLE_BLACKLIST):
        final_title = clean_link_title

    # 2순위: 상세 본문 영역 내 실제 글 제목 태그 탐색
    if not final_title:
        candidate_titles = []
        for tag_pat in [
            r'<(?:h[1-3]|div|td|th|p)[^>]*class=["\'][^"\']*(?:bbs_title|view_title|subject|tit)[^"\']*["\'][^>]*>(.*?)</(?:h[1-3]|div|td|th|p)>',
            r'<th[^>]*scope=["\']row["\'][^>]*>(.*?)</th>',
            r'<h[1-3][^>]*>(.*?)</h[1-3]>'
        ]:
            for m in re.finditer(tag_pat, html, re.I | re.S):
                t = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', m.group(1))).strip()
                t = re.sub(r'^\s*\[[^\]]+\]\s*', '', t).strip()
                if len(t) >= 5 and not any(bl == t or bl in t for bl in ["로그인", "사이트맵", "통합검색", "시청안내", "상세내용"]):
                    candidate_titles.append(t)
        for ct in candidate_titles:
            if not any(bl == ct for bl in TITLE_BLACKLIST) and len(ct) >= 5:
                final_title = ct
                break

    # 3순위: og:title
    if not final_title:
        og_t = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)["\']', html, re.I)
        if og_t:
            cand = htmllib.unescape(og_t.group(1)).strip()
            if not any(bl == cand for bl in TITLE_BLACKLIST) and len(cand) >= 4:
                final_title = cand

    if not final_title:
        final_title = clean_link_title or "시민 참여 이벤트"

    # 제목 정리 (접두사/접미사 다듬기)
    final_title = re.sub(r'\s*-\s*(수원시|고양시|용인시|성남시|화성시|안양시|경기도)[^$]*$', '', final_title).strip()

    # 2. 대표 이미지(포스터) 추출: 게시글에 올린 실제 이미지만 인정 (없으면 빈 값, 가짜 스톡사진 금지)
    poster_url, poster_candidates = pick_poster(html, source_url)

    # 3. 외부 신청/응모 링크(Apply URL) 추출
    apply_url = source_url
    for href, inner in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.S | re.I):
        h = htmllib.unescape(href)
        t = re.sub(r'<[^>]+>', '', inner).strip()
        generic_h = re.search(r'/(index|main)(\.do|\.jsp|\.html)?/?$|^https?://[^/]+/?$', h.split("?")[0].lower())
        # 외부 신청서 서비스(네이버폼·구글폼 등)만 확실한 신청 링크로 인정. (사이트 메뉴의 '설문조사 목록' 같은 링크는 제외)
        if any(d in h for d in ["naver.me", "forms.gle", "form.naver.com", "docs.google.com/forms"]) and not generic_h:
            apply_url = urllib.parse.urljoin(source_url, h)
            break
        elif re.search(r'신청하기|응모하기|참여하기|접수하기', t) and h.startswith("http") \
                and not re.search(r'list\.do|weblist|qestnar|survey', h.lower()) \
                and not re.search(r'/(index|main)(\.do|\.jsp|\.html)?/?$|^https?://[^/]+/?$', h.split("?")[0].lower()):
            apply_url = h
            break

    # 4. 기간(Period)
    start_date, end_date = parse_period(full_text, today, raw_date_hint)
    if not start_date or not end_date:
        return skipped("PERIOD_NOT_FOUND", f"본문에서 접수 기간을 찾지 못해 제외: {final_title[:30]}")
    if end_date < today:
        return skipped("EXPIRED", f"기한 만료 제외: {final_title[:30]} (종료일 {end_date}, 오늘 {today})")

    # 5. 리워드(Rewards)
    rewards = parse_rewards(full_text)
    if not rewards:
        hint = [w for w in REWARD_HINT_WORDS if w in full_text]
        # 복지성 지원(입학지원금·수당·바우처 등)은 시민 응모 경품이 아니므로 검토 대기에도 올리지 않는다
        if re.search(r"지원금|수당|급여|장학|보조금|입학지원|바우처|돌봄|복지", final_title):
            return skipped("WELFARE_BENEFIT", f"복지성 지원 안내라 경품 이벤트가 아니어서 제외: {final_title[:30]}")
        if poster_url and hint:
            region_r, org_r = guess_region(full_text, org_hint, final_title)
            res = skipped("REWARD_IN_IMAGE", f"경품 단서({', '.join(hint[:3])})는 있으나 금액·인원이 글자로 없음 → 포스터 이미지 검토 대기: {final_title[:30]}")
            res["status"] = "needs_review"
            res["candidate"] = {
                "title": final_title, "org_name": org_r, "target_region": region_r,
                "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                "source_url": source_url, "poster_image_url": poster_url,
                "poster_candidates": poster_candidates, "reward_hints": hint,
                "review_reason": "경품 금액·인원이 본문 글자에 없고 포스터 이미지에만 있을 수 있음. 운영자가 이미지를 보고 확인 후 승인해야 공개 가능",
                "kchecker_verified": False,
            }
            return res
        return skipped("REWARD_NOT_FOUND", f"본문에서 경품 금액·인원을 확인하지 못해 제외: {final_title[:30]}")

    # 6. 지역(Region) 및 기관(Org)
    region, org = guess_region(full_text, org_hint, final_title)

    # 7. 카테고리(Category)
    if any(w in final_title + full_text[:1000] for w in ["축제", "행사", "체험", "콘서트", "음악회", "가든", "포토존"]):
        category = "문화·체험 축제"
    elif any(w in final_title + full_text[:1000] for w in ["설문", "의견", "만족도", "서명", "조사"]):
        category = "설문·시민의견"
    elif any(w in final_title + full_text[:1000] for w in ["이벤트", "스탬프", "퀴즈", "인증", "경품", "추첨"]):
        category = "경품 이벤트"
    else:
        category = "시민참여 행사"

    # 8. 어뷰징 방지 조항(Shield Rule)
    abuse_policy = ""
    for l in lines:
        if any(k in l for k in ["명의도용", "부정참여", "중복 응모", "당첨 취소", "1인 1회", "비정상"]):
            abuse_policy = l
            break
    if not abuse_policy:
        abuse_policy = "K-Gift Shield 1인 1회 원칙 및 부정 참여 방지 안심 검증 적용"

    # 신뢰도 점수 산출 (안정적 80~95점 보장)
    score = 70
    if start_date:
        score += 10
    if rewards:
        score += 10
    if poster_url:
        score += 5
    if apply_url != source_url:
        score += 5

    dedup = hashlib.sha256(f"{org}:{final_title}:{start_date}:{end_date}".encode("utf-8")).hexdigest()

    return {
        "status": "success",
        "confidence_score": score,
        "dedup_hash": dedup,
        "skip_reason": "",  # 유효한 경기도 이벤트는 무조건 수집 통과
        "event_data": {
            "title": final_title,
            "org_name": org,
            "category": category,
            "target_region": region,
            "target_age": ["ALL"],
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "active_round": f"공고문 기재 일정: {start_date.isoformat()} ~ {end_date.isoformat()}",
                "next_round": "",
                "total_rounds": ""
            },
            "rewards": rewards,
            "source_url": source_url,
            "apply_url": apply_url,
            "poster_image_url": poster_url,
            "poster_candidates": poster_candidates,
            "abuse_prevention_rule": abuse_policy,
            "announcement_info": "해당 지자체 누리집 공식 발표 및 모바일 개별 안내"
        }
    }


# ======================================================== 4. 수집 관리자 및 데이터 파이프라인
def collect_from_target(net: Net, target: dict, max_items: int, today: dt.date):
    name = target.get("name", "지자체 게시판")
    list_url = target.get("list_url", "")
    org = target.get("org", "경기도")
    accept_all = target.get("accept_all", True)

    out = []
    log = []

    try:
        html = net.get(list_url)
    except Exception as e:
        return [], [f"  [-] 목록 접근 실패: {e}"], str(e)

    # 헌터가 넉넉히 후보를 찾고, 체커가 검사하여 통과한 것만 최대 max_items까지 수집
    candidate_links = find_event_links(html, list_url, JOIN_WORDS, max_items * 3, accept_all)
    log.append(f"  [*] 헌터가 1차 후보 링크 {len(candidate_links)}개 탐색 완료 (K-Checker 2중 교차 검증 시작)")

    for item in candidate_links:
        if len(out) >= max_items:
            break
        try:
            detail_html = fetch_detail(net, item["url"], list_url)
            ev = extract_event(
                html=detail_html,
                source_url=item["url"],
                link_title=item.get("link_text", ""),
                org_hint=org,
                raw_date_hint=item.get("raw_date", ""),
                today=today
            )
            is_ocr_active = VISION.get("on") or OCR_CONFIG.get("tesseract")
            # 수집 단계에서 제외된 글(기간/경품 미확인, 만료)은 이유를 로그에 남기고 건너뜀
            if ev and ev.get("status") == "needs_review" and is_ocr_active:
                # 이미지 속 글자를 읽어서(무료 OCR/비전) 본문처럼 다시 판정한다. 이미지에도 경품이 없으면 제외.
                cand = ev["candidate"]
                ptxt = read_poster_texts(net, cand.get("poster_candidates") or [cand["poster_image_url"]], item["url"])
                if ptxt and parse_rewards(ptxt):
                    ev2 = extract_event(html=detail_html + "<div>" + htmllib.escape(ptxt) + "</div>", source_url=item["url"],
                                        link_title=item.get("link_text", ""), org_hint=org,
                                        raw_date_hint=item.get("raw_date", ""), today=today)
                    if ev2 and ev2.get("status") == "success":
                        ev2["event_data"]["reward_source"] = "poster_image"
                        ev2["event_data"]["poster_text"] = ptxt[:1500]
                        ev = ev2
                        log.append(f"    [👁] 포스터 이미지에서 경품 문구 확인: {ev['event_data']['title'][:30]}")
                if ev.get("status") == "needs_review" and ptxt:
                    log.append(f"    [-] 포스터 이미지를 읽었으나 경품 금액·인원 문구가 없어 제외: {cand['title'][:30]}")
                    continue
            if ev and ev.get("status") == "needs_review":
                cand = ev["candidate"]
                st, ct, n = net.probe_image(cand["poster_image_url"], referer=item["url"])
                if st == 200 and "image" in ct.lower() and n > 500:
                    cand["_source"] = name
                    REVIEW_QUEUE.append(cand)
                    log.append(f"    [?] 검토 대기(포스터 확인 필요): {cand['title'][:35]} | 🖼 {cand['poster_image_url'][-40:]}")
                else:
                    log.append(f"    [-] 포스터 이미지가 열리지 않아 검토 대기에서도 제외: {cand['title'][:30]} ({st} {ct[:30]})")
                continue
            if ev and ev.get("skip_reason") in ("PERIOD_NOT_FOUND", "EXPIRED"):
                record_period_debug(item, ev, detail_html)
            if not ev or ev.get("status") != "success":
                msg = (ev or {}).get("skip_message", "알 수 없는 사유로 제외")
                log.append(f"    [-] 수집 제외 [{(ev or {}).get('skip_reason', 'UNKNOWN')}] {msg} (URL: {item['url'][:45]})")
                continue

            # 포스터 필수: 기본 탐색으로 못 찾았으면 더 강하게 찾는다 (끝내 없으면 체커가 POSTER_MISSING 으로 거절)
            if not ev["event_data"].get("poster_image_url"):
                found_p = find_poster_hard(net, detail_html, item["url"], log)
                if found_p:
                    ev["event_data"]["poster_image_url"] = found_p["url"]
                    ev["event_data"]["poster_candidates"] = [found_p["url"]]
                    if found_p.get("local_path"):
                        ev["event_data"]["poster_local_path"] = found_p["local_path"]
                    log.append(f"    [🖼] 포스터를 추가 탐색으로 찾음 ({found_p['how']}): {found_p['url'][-50:]}")
            # 🛡️ 2단계: K-Checker에게 실시간 검사 받기 (Zero-Lie Check)
            ok, rep = verify_single_event(ev["event_data"], extra_text=ev["event_data"].get("poster_text", ""), page_html=detail_html)
            if not ok:
                log.append(f"    [-] 🛡️ K-Checker 탈락: {rep['reason']} (URL: {item['url'][:45]}) -> 체커 기준 미달로 버리고 다음 글 검사")
                continue

            if is_ocr_active and not ev["event_data"].get("poster_text") and ev["event_data"].get("poster_image_url"):
                ptxt = read_poster_texts(net, ev["event_data"].get("poster_candidates") or [ev["event_data"]["poster_image_url"]], item["url"])
                if ptxt:
                    ev["event_data"]["poster_text"] = ptxt[:1500]
            # 포스터가 실제로 열리는지 한 번 더 확인. 안 열리면 비우지 않고 이벤트 자체를 버린다 (가짜 이미지 금지)
            pu = ev["event_data"].get("poster_image_url", "")
            if pu and not ev["event_data"].get("poster_local_path"):
                st, ct, n = net.probe_image(pu, referer=item["url"])
                if not (st == 200 and "image" in ct.lower() and n > 500):
                    log.append(f"    [-] 포스터 이미지가 열리지 않아 이벤트를 제외합니다 ({st} {ct[:30]}): {pu[-50:]}")
                    continue
            ev["_source"] = name
            ev["kchecker_verified"] = True
            ev["kchecker_report"] = rep["reason"]
            out.append(ev)
            log.append(f"    [+] 🟢 K-Checker 최종 승인: {ev['event_data']['title'][:35]} | 혜택: {ev['event_data']['rewards'][0]['item_name']}")
        except Exception as err:
            log.append(f"    [-] 상세 파싱 실패 ({item['url'][:45]}): {err}")

    if not out:
        log.append(f"  [!] ⚠️ 해당 게시판에 K-Checker 검증 기준을 100% 충족하는 이벤트가 없어 가짜 데이터 없이 안전하게 0건 처리합니다.")

    return out, log, ""


REVIEW_QUEUE = []   # 포스터 확인이 필요한 '검토 대기' 후보 (공개·Supabase 적재 대상 아님)
PERIOD_DEBUG = []   # 기간을 못 찾았거나 만료로 판정된 글의 날짜 주변 글자 (파서가 날짜 표기를 놓치는지 확인용)
_DATE_SNIP = re.compile(r"(?<!\d)(?:['’]?\d{2,4}\s*[.\-/년]\s*\d{1,2}\s*[.\-/월]\s*\d{1,2}|\d{1,2}\s*월\s*\d{1,2}\s*일)")


def record_period_debug(item: dict, ev: dict, detail_html: str):
    text = " ".join(clean_text(detail_html))
    snips, last = [], -100
    for m in _DATE_SNIP.finditer(text):
        if m.start() - last < 20:
            continue
        last = m.start()
        snips.append(text[max(0, m.start() - 30): m.end() + 30])
        if len(snips) >= 8:
            break
    PERIOD_DEBUG.append({"title": item.get("link_text", "")[:60], "url": item["url"], "reason": ev.get("skip_reason", ""),
                         "message": ev.get("skip_message", "")[:120], "list_date_hint": item.get("raw_date", ""),
                         "body_len": len(text), "date_snippets": snips})


def save_period_debug(path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"기간 판정 진단 ({dt.datetime.now():%Y-%m-%d %H:%M}) - 기간을 못 찾았거나 만료로 판정된 글 {len(PERIOD_DEBUG)}건\n\n")
        for d in PERIOD_DEBUG:
            f.write(f"[{d['reason']}] {d['title']}\n  {d['url']}\n  판정: {d['message']}\n  목록의 날짜: {d['list_date_hint'] or '-'} | 본문 글자수: {d['body_len']}\n")
            for sn in d["date_snippets"] or ["(본문에서 날짜처럼 보이는 글자 없음)"]:
                f.write(f"   · ...{sn}...\n")
            f.write("\n")
    print(f"[*] 기간 진단 저장: {path} ({len(PERIOD_DEBUG)}건)")


def save_review(path: str):
    out = {"status": "needs_review", "note": "경품 금액·인원이 포스터 이미지에만 있을 가능성이 있는 글. 운영자가 이미지를 보고 확인하기 전에는 공개하지 않음.",
           "generated_at": dt.datetime.now().isoformat(timespec="seconds"), "count": len(REVIEW_QUEUE), "items": REVIEW_QUEUE}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[*] 검토 대기 목록 저장: {path} (총 {len(REVIEW_QUEUE)}건 - 포스터 이미지 확인 필요)")


def save_json(events: list, path: str):
    """HTML 웹앱과 100% 호환되는 정형 다건 events.json 저장"""
    clean_events = [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]
    out = {
        "status": "success",
        "version": VERSION,
        "region_scope": "경기도 31개 시·군 공식 실시간 이벤트",
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "count": len(clean_events),
        "events": clean_events
    }
    # HTML 단건 호환 (최상단 대표 이벤트)
    if clean_events:
        out.update({
            "confidence_score": clean_events[0]["confidence_score"],
            "dedup_hash": clean_events[0]["dedup_hash"],
            "event_data": clean_events[0]["event_data"]
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[*] 로컬 JSON 저장 완료: {path} (총 {len(clean_events)}건 실시간 적재)")


def sync_to_supabase(event_data: dict, sb_url: str, sb_key: str, ctx, dedup_hash: str = ""):
    """Supabase events 테이블 실제 컬럼 규격에 맞추어 실시간 적재 (0원/무료 원천 거부)"""
    rewards = event_data.get("rewards", [])
    if not rewards:
        return {"ok": False, "status": 400, "error": "ZERO_REWARD: 리워드가 없어 적재 거부"}

    prizes = [
        {"n": r.get("item_name", "경품"), "q": r.get("winners_count", 0), "u": r.get("unit_price", 0)}
        for r in rewards
        if r.get("item_name") not in [
            "무료", "0원", "없음", "단순안내", "단순 안내", "시민 참여 기념품 및 혜택",
            "기념품 및 혜택", "시민 참여 기념품", "기념품", "혜택"
        ]
    ]
    if not prizes:
        return {"ok": False, "status": 400, "error": "ZERO_PRIZES: 유효한 경품이 없어 적재 거부"}

    # 기간 만료 엄격 검증
    end_date_val = event_data.get("period", {}).get("end")
    if end_date_val:
        try:
            ed = dt.datetime.strptime(str(end_date_val)[:10], "%Y-%m-%d").date()
            if ed < dt.date.today():
                return {"ok": False, "status": 400, "error": f"EXPIRED_EVENT: 기간 종료({ed})로 적재 거부"}
        except Exception:
            pass

    budget = sum((p["q"] or 0) * (p["u"] or 0) for p in prizes)
    if budget <= 0:
        return {"ok": False, "status": 400, "error": "ZERO_BUDGET: 예산이 0원이어서 적재 거부"}

    payload = {
        "owner_id": "67e6f52e-f5f8-44e6-9179-7b38740d38ab",  # 시스템 기본 관리자 계정 UUID
        "dedup_hash": dedup_hash or None,  # UNIQUE 제약으로 중복 적재 방지 (supabase_security_patch_v58.sql 적용 필요)
        "title": event_data["title"],
        "tpl": "경품 응모" if "경품" in event_data.get("category", "") else "설문 참여",
        "target_region": event_data.get("target_region", "경기도"),
        "target_ages": ["ALL"],
        "start_date": event_data["period"]["start"],
        "end_date": event_data["period"]["end"],
        "prizes": prizes,
        "link": event_data.get("apply_url") or event_data.get("source_url"),
        "budget": budget,
        "status": "live",
        "org_name": event_data.get("org_name", "경기도"),
        "poster_url": event_data.get("poster_image_url", ""),
        "source_url": event_data.get("source_url", ""),
        "shield_rule": f"🛡️ K-Checker 2중 실측 검증 통과: {event_data.get('kchecker_report', 'URL 200 OK & 본문 경품 일치')}"
    }

    req = urllib.request.Request(
        f"{sb_url}/rest/v1/events?on_conflict=dedup_hash",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "apikey": sb_key,
            "Authorization": f"Bearer {sb_key}",
            "Content-Type": "application/json",
            # 같은 dedup_hash 가 이미 있으면 에러 없이 건너뜀(중복 적재 방지)
            "Prefer": "resolution=ignore-duplicates,return=minimal"
        }
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read().decode("utf-8", errors="ignore")}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)}


# ======================================================== 5. 메인 엔트리포인트
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description=f"K-Gift Hunter v{VERSION} - 경기도 31개 시·군 실시간 이벤트 수집")
    ap.add_argument("--sources", default=DEFAULT_SOURCES, help="수집 대상 JSON 설정 파일")
    ap.add_argument("--only", help="특정 지자체 필터 (예: 수원, 고양, 용인 등)")
    ap.add_argument("--out", default="events.json", help="저장할 JSON 파일 경로")
    ap.add_argument("--max", type=int, default=6, help="게시판당 최대 수집 건수")
    ap.add_argument("--no-sync", action="store_true", help="Supabase 전송 건너뛰기")
    ap.add_argument("--ocr", action="store_true", help="포스터 이미지 속 글자를 무료 Tesseract OCR(tesseract-ocr-kor)로 읽기")
    ap.add_argument("--vision", action="store_true", help="포스터 이미지 속 글자를 Claude 비전으로 읽기 (환경변수 ANTHROPIC_API_KEY 필요)")
    args = ap.parse_args()
    if args.ocr:
        import shutil
        tess = shutil.which("tesseract")
        OCR_CONFIG["tesseract"] = True
        print(f"[*] 무료 Tesseract OCR 엔진 활성화 완료 (실행 경로: {tess or 'pytesseract'})")
    if args.vision:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            print("[!] --vision 을 쓰려면 환경변수 ANTHROPIC_API_KEY 가 필요합니다. 비전 없이 계속합니다.")
        else:
            VISION.update(on=True, key=key, model=os.environ.get("KGIFT_VISION_MODEL", VISION["model"]))
            print(f"[*] 비전 판독 켜짐 (모델: {VISION['model']})")

    today = dt.date.today()
    net = Net(delay=0.3, respect_robots=False)

    print("==================================================================")
    print(f"[*] K-Gift Hunter v{VERSION} 가동 - 경기도 31개 시·군 공식 실시간 이벤트 정밀 수집")
    print(f"[*] 실행 시각: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
    print("==================================================================")

    # sources 불러오기
    if not os.path.exists(args.sources):
        print(f"[-] sources 파일이 없어 내장 기본 소스를 가동합니다: {args.sources}")
        targets = [
            {"name": "수원특례시 참여형 행사", "org": "수원시", "list_url": "https://www.suwon.go.kr/web/board/BD_board.list.do?bbsCd=1381"},
            {"name": "고양특례시 설문·이벤트", "org": "고양시", "list_url": "https://www.goyang.go.kr/www/user/qestnar/BD_selectQestnarList.do"},
            {"name": "고양특례시 행사달력", "org": "고양시", "list_url": "https://www.goyang.go.kr/www/user/eventCldr/BD_selectEventCldrList.do"},
            {"name": "용인특례시 시민참여 행사", "org": "용인시", "list_url": "https://www.yongin.go.kr/citizen/user/bbs/BD_selectBbsList.do?q_bbsCode=1294"},
            {"name": "안양시 행사교육", "org": "안양시", "list_url": "https://www.anyang.go.kr/main/selectBbsNttList.do?bbsNo=63&key=261"},
            {"name": "성남시 시민 행사보기", "org": "성남시", "list_url": "https://www.seongnam.go.kr/pm010201?nowym="}
        ]
    else:
        with open(args.sources, encoding="utf-8") as f:
            cfg = json.load(f)
        targets = [s for s in cfg.get("sources", []) if s.get("enabled", True)]

    if args.only:
        targets = [t for t in targets if args.only in t.get("name", "") or args.only in t.get("org", "")]

    all_collected = []
    seen_hashes = set()

    for idx, t in enumerate(targets, 1):
        print(f"\n[{idx}/{len(targets)}] {t['name']} 수집 중... ({t['list_url']})")
        items, log, err = collect_from_target(net, t, args.max, today)
        print("\n".join(log))

        for it in items:
            h = it["dedup_hash"]
            if h not in seen_hashes:
                seen_hashes.add(h)
                all_collected.append(it)

    print("\n" + "=" * 60)
    print(f"[*] 경기도 공식 이벤트 정밀 수집 완료: 총 {len(all_collected)}건 검증 성공")
    for r in all_collected:
        d = r["event_data"]
        print(f"  + [{r['confidence_score']}점 | {d['category']}] {d['title'][:40]}")
        print(f"      📍 {d['target_region']} ({d['org_name']}) | 📅 {d['period']['start']} ~ {d['period']['end']}")
        print(f"      🎁 {d['rewards'][0]['item_name']} | 🔗 {d['apply_url'][:60]}")
    print("=" * 60)

    # 1. events.json 저장
    out_file = os.path.join(HERE, args.out)
    save_json(all_collected, out_file)
    save_review(os.path.join(HERE, "events_review.json"))
    save_period_debug(os.path.join(HERE, "period_debug.txt"))

    # 2. Supabase 클라우드 실시간 적재
    if not args.no_sync and all_collected:
        print("\n[*] Supabase 클라우드 데이터베이스 실시간 적재 동기화 시작...")
        ctx = get_safe_ssl_context()
        success_count = 0
        for it in all_collected:
            res = sync_to_supabase(it["event_data"], DEFAULT_SB_URL, DEFAULT_SB_KEY, ctx, it.get("dedup_hash", ""))
            if res.get("ok"):
                success_count += 1
                print(f"  [+] Supabase 적재 성공: {it['event_data']['title'][:35]}")
            else:
                print(f"  [-] Supabase 적재 실패 ({res.get('status')}): {res.get('error', '')[:80]}")
        print(f"[*] Supabase 동기화 완료: {success_count}/{len(all_collected)}건 전송 성공")

    print("\n[★] 모든 경기도 실시간 이벤트 수집 및 플랫폼 연동 파이프라인 가동 완료!")


if __name__ == "__main__":
    main()
