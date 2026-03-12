# NVD + EPSS Vulnerability Intelligence Project

PostgreSQL 기반으로 NVD CVE 데이터를 수집하고, EPSS 점수를 별도 데이터베이스에 저장한 뒤 향후 웹 대시보드 및 취약점 분석 플랫폼으로 확장하기 위한 개인 연구 프로젝트.

이 프로젝트의 목표는 **취약점 데이터 파이프라인 구축**이다.  
NVD 데이터를 정규화하여 저장하고, EPSS와 결합하여 취약점 우선순위 분석이 가능한 기반을 만드는 것을 목표로 한다.

---

# 1. 프로젝트 목적

이 프로젝트는 다음 목표를 가진다.

- NVD API를 이용한 CVE 데이터 자동 수집
- PostgreSQL에 취약점 데이터 구조화 저장
- 변경된 CVE 자동 업데이트
- EPSS 점수 일별 저장
- 향후 웹 기반 취약점 분석 대시보드 구축

최종적으로는 다음과 같은 분석을 제공하는 것을 목표로 한다.

- 최근 180일 신규 취약점 통계
- 벤더별 취약점 분포
- 제품별 취약점 분포
- CVSS 점수 분포
- EPSS 기반 취약점 우선순위
- exploit 가능성 분석

---

# 2. 사용 기술

현재 프로젝트에서 사용되는 기술 스택

Backend / Data
- Python
- PostgreSQL
- pgAdmin 4

Data Sources
- NVD CVE API 2.0
- NVD CVE Change History API
- EPSS API (FIRST)

향후 계획 기술

Backend
- FastAPI

Frontend
- React 또는 Next.js

Data Visualization
- Chart.js 또는 ECharts

---

# 3. 프로젝트 폴더 구조

현재 작업 디렉토리 구조
CVE/
├─ README.md
├─ cve_crawler.py
├─ epss_daily_sync.py
├─ nvd_sync.py
├─ nvdcve_crawler.py
└─ nvdupdatecve.py



파일 설명

cve_crawler.py  
초기 NVD CVE 수집 테스트용 스크립트

nvd_sync.py  
NVD API를 사용하여 CVE 데이터를 수집하는 기본 스크립트

nvdcve_crawler.py  
NVD 취약점 데이터를 PostgreSQL에 저장하기 위한 크롤러

nvdupdatecve.py  
NVD 변경 이력 기반 증분 업데이트 스크립트

epss_daily_sync.py  
EPSS 데이터를 매일 받아 `epss_db`에 저장하는 스크립트

---

# 4. PostgreSQL 데이터베이스 구조

현재 PostgreSQL 서버에 생성된 데이터베이스
Databases
├─ cve
├─ epss_db
├─ nvd_cve
└─ vendor_product_mv


## 4.1 nvd_cve

NVD 취약점 데이터를 저장하는 메인 데이터베이스

저장 데이터

- CVE 기본 정보
- CVSS v2 / v3 / v4
- CWE
- CPE
- References
- exploit 관련 정보
- raw JSON

주요 테이블 (예정)
cves
cve_metrics
cve_cwes
cve_cpes
cve_references
sync_state


---

## 4.2 epss_db

EPSS 점수를 저장하는 별도 데이터베이스

EPSS는 매일 값이 변경되기 때문에 NVD와 분리하여 관리한다.

테이블 구조
epss_scores
cve_id(Primary Key)
score_date
epss_score
percentile
created_at


이 구조는 EPSS 점수의 **일별 이력 저장**을 가능하게 한다.

---

# 5. NVD 데이터 수집 방식

NVD API 2.0을 사용하여 취약점 데이터를 수집한다.

기본 API
https://api.first.org/data/v1/epss?cve=CVE-2022-25204&scope=time-series
https://api.first.org/data/v1/epss?order=!epss
페이지 단위로 데이터를 가져온다.

예
resultsPerPage = 2000
startIndex = 0


수집 흐름

1. startIndex 0부터 시작
2. resultsPerPage 만큼 데이터 수집
3. startIndex 증가
4. 모든 CVE 수집 완료까지 반복

터미널 출력 예
Processing page: 0
Processing page: 2000
Processing page: 4000


이 숫자는 페이지 번호가 아니라 **CVE 인덱스 위치**이다.

---

# 6. NVD API Key 사용

NVD API는 API key 없이도 사용할 수 있지만 rate limit이 매우 낮다.

따라서 API key를 사용한다.

PowerShell에서 환경변수 설정

$env:NVD_API_KEY="YOUR_API_KEY"
python nvd_sync.py

api_key = os.getenv("NVD_API_KEY")



API 호출 시 header에 포함된다.

---

# 7. NVD 증분 업데이트 계획

전체 CVE 데이터를 한 번 수집한 이후에는 **변경된 CVE만 업데이트**한다.

이를 위해 NVD Change History API를 사용한다.

API
https://services.nvd.nist.gov/rest/json/cvehistory/2.0


동작 방식

1. 변경된 CVE ID 조회
2. 해당 CVE ID 목록 수집
3. CVE API로 최신 데이터 다시 조회
4. PostgreSQL에서 해당 CVE 관련 레코드 삭제
5. 최신 데이터로 재삽입

이 방식은 **데이터 정합성 유지에 가장 안전한 방법**이다.

---

# 8. EPSS 데이터 수집

단일 항목: 지난 30일 동안 CVE XXXX에 대한 EPSS 점수를 표시합니다.https://api.first.org/data/v1/epss?cve=CVE-2022-25204&scope=time-series

가장 높은 점수를 받은 상위 N개의 CVE를 표시합니다. 즉, 가장 높은 점수를 받은 100개의 CVE를 보여줍니다(확률 또는 백분위 기준 모두 가능).https://api.first.org/data/v1/epss?order=!epss

EPSS CSV

수집 흐름

1. EPSS CSV 다운로드
2. CSV 파싱
3. PostgreSQL epss_db에 저장
4. (cve_id, score_date) 기준 UPSERT

Python 스크립트
epss_daily_sync.py



자동화 예정

- Windows Task Scheduler
- Linux cron

---

# 9. 향후 웹 플랫폼 계획

향후 이 데이터베이스를 기반으로 웹 플랫폼을 개발할 예정이다.

웹에서 제공할 기능

최근 180일 취약점 분석

- 신규 CVE 수
- 벤더 분포
- 제품 분포
- CVSS 분포
- EPSS 상위 취약점

취약점 검색

- CVE 검색
- Vendor 검색
- Product 검색

우선순위 분석

- CVSS + EPSS 기반 위험도
- Known exploited vulnerabilities

---

# 10. 향후 개발 계획

다음 단계

1. NVD 전체 데이터 적재 완료
2. NVD Change History 기반 증분 업데이트 구현
3. EPSS daily sync 자동화
4. FastAPI 백엔드 개발
5. 취약점 분석 API 구현
6. React 기반 웹 대시보드 개발

---

# 11. 장기 목표

이 프로젝트의 장기 목표는 다음과 같다.

- 취약점 인텔리전스 플랫폼 구축
- 자동 취약점 분석
- exploit 가능성 기반 우선순위 분석
- 보안 연구 데이터 플랫폼 구축
