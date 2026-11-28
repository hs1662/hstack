# hstack graph v1 장기 작업자 규약

긴 작업을 맡은 작업자가 지켜야 할 운영 규칙이다. 맥락 관리, 재시작과 인계, 로컬 검사, 이탈 감지, 예산 계산을 다룬다. 이 문서는 규약이다. 아래 셸 예시 말고는 실행 가능한 새 옵션을 만들지 않는다.

## 1. 관찰 기록 관리

- 최근 M=10 턴의 원문 관찰은 그대로 둔다. 관찰 개수가 아니라 턴 수로 센다.
- 12턴 경계마다 한 번에 묶어서 정리한다. 매 턴 조금씩 고치지 않는다. 그래야 프롬프트 캐시의 앞부분이 안정적으로 유지된다.
- 정리 대상은 그보다 오래된 관찰(OBSERVATIONS)뿐이다. 각 항목을 다음 한 줄로 바꾼다.

```text
[Masked: <cmd> exit=<code> -> cas://<sha>]
```

- 추론, 행동, 오류 코드는 지우지 않는다. 변경 불가로 표시된 원문 관찰도 그대로 둔다.
- 원문은 내용 주소 저장소(cas)에 남긴다. 다시 필요하면 `<sha>` 로 꺼내 읽는다.

## 2. 정리 재시작과 고정 인계

- 실제로 관찰된 유효 입력 사용량이 55% 에서 65% 사이에 들면 미리 깨끗하게 재시작한다. 한계에 닿을 때까지 버티지 않는다.
- 재시작 전에 고정 인계 메모를 남긴다. 목표, 완료 항목, 남은 항목, 열린 오류 코드, 최근 증거 위치를 적는다.
- 사용량 수치가 응답에 없으면 추정하지 않는다. 그 턴은 사용량 없음으로 두고 재시작 판단에 쓰지 않는다.
- 바이트와 토큰 사이에 고정 환산 비율을 쓰지 않는다.

## 3. 로컬 검사

- 모든 로컬 검사에는 강제 시간 제한을 건다. 시간이 지나면 프로세스를 끝내고 실패로 기록한다.
- 큰 묶음은 결정적 표본으로 먼저 돌릴 수 있다. 같은 파일 목록이면 언제나 같은 파일이 뽑힌다.
- node:test 자체에는 --sample 옵션이 없다. 여기서 말하는 `--sample` 은 아래 셸 래퍼의 동작 방식일 뿐이다. 래퍼가 파일을 골라서 `node --test` 에 넘긴다.
- `--sample` 은 비용 계층이 아니다. 경로의 sha256 순서로 고른 표본이다. 테스트 실행 계층(fast, full, fault)과는 별개다.
- 실패하면 한 줄짜리 ERROR 색인을 남기고 전체 로그는 따로 보관한다. 색인 줄에는 종료 코드, 오류 코드, 로그 경로가 들어간다.
- 오류 코드는 공통 규약대로 `Error.code` 문자열을 쓴다. 시간 초과는 `E_CHECK_TIMEOUT`, 그 밖의 실패는 `E_CHECK_FAILED` 이다.

### 셸 예시 (Node 18 이상, bash, coreutils timeout)

```sh
# hstack-long-worker-sample
set -u
SAMPLE_N="${SAMPLE_N:-8}"
CHECK_TIMEOUT="${CHECK_TIMEOUT:-300}"
TEST_GLOB="${TEST_GLOB:-test/*.test.mjs}"
OUT_DIR="${OUT_DIR:-${TMPDIR:-/tmp}/long-worker}"
mkdir -p "$OUT_DIR"

# 인자 없이 부르면 전체를 돌리고, --sample 을 주면 표본만 돌린다.
limit=0
[ "${1:-}" = "--sample" ] && limit="$SAMPLE_N"

# 경로의 sha256 순서로 정렬해 앞의 limit 개를 고른다. 0 이면 전부 쓴다.
mapfile -t picked < <(node -e '
const { createHash } = require("node:crypto");
const n = Number(process.argv[1]);
const rows = process.argv.slice(2)
  .map((f) => [createHash("sha256").update(f).digest("hex"), f])
  .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
(n > 0 ? rows.slice(0, n) : rows).forEach(([, f]) => console.log(f));
' "$limit" $TEST_GLOB)

for f in "${picked[@]}"; do echo "SAMPLE $f"; done

log="$OUT_DIR/check-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
timeout --kill-after=5 "$CHECK_TIMEOUT" node --test "${picked[@]}" >"$log" 2>&1
code=$?
if [ "$code" -ne 0 ]; then
  case "$code" in
    124|137) err=E_CHECK_TIMEOUT ;;
    *) err=E_CHECK_FAILED ;;
  esac
  printf 'ERROR exit=%s code=%s log=%s\n' "$code" "$err" "$log" >>"$OUT_DIR/ERROR.index"
fi
exit "$code"
```

사용 예:

```sh
SAMPLE_N=4 CHECK_TIMEOUT=120 TEST_GLOB='test/graph-*.test.mjs' bash sample.sh --sample
CHECK_TIMEOUT=900 bash sample.sh
```

이 스크립트를 `node:test` 안에서 띄울 때는 자식 환경에서 `NODE_TEST_CONTEXT`를 지운다. 중첩 실행의 동작은 버전에 따라 다르다. Node 22.23.5에서는 이 값이 남으면 안쪽 검사가 파일을 실행하지 않고 0으로 끝났고, Node 18.20.8에서는 파일을 실행했다.

표본 통과는 전체 통과가 아니다. 완료를 주장하려면 `--sample` 없이 전체를 시간 제한 안에서 다시 돌린다.

## 4. 이탈 감지 (k=2)

- 의미 또는 형식 이탈 경보가 두 번 쌓이면(k=2) 작업자를 의심 상태로 둔다. 경보 하나로는 상태를 바꾸지 않는다.
- 의심 상태에서 외부 탐침이 실패하거나 schemaError 를 내면 기다리지 않고 바로 상위로 올린다. 이때 검증된 변경 불가 고정본(pin)을 걸어 이후 판단의 기준으로 삼는다.
- 이 감지는 완료 관문이 아니다. 경보가 없다고 완료로 보지 않는다. 완료는 실제 검사 결과로만 판단한다.

## 5. 예산 계산

사용량이 관찰된 경우, 새로 믿을 수 있는 예산은 다음과 같다.

```text
B     = max(0, W_eff - reservedTokens)
issue = min(512, floor(0.1 * B))
wave  = floor(0.3 * B)
```

- `W_eff` 는 실제로 관찰된 유효 창 크기다. 추정값을 넣지 않는다.
- 사용량이 없으면 토큰 예산을 만들지 않는다. 대신 독립된 바이트 한도 `maxInlineBytesPerNode` 와 `maxInlineBytesPerWave` 로 제한한다.
- 그때 토큰 필드(`B`, `issue`, `wave` 등)는 명시적으로 `null` 로 적는다. 바이트 한도를 토큰으로 환산하지 않는다. null 이 몇 번 나왔는지 세는 별도 지표도 만들지 않는다.

## 6. 하지 않는 것

- 구현되지 않은 실행 옵션을 있는 것처럼 쓰지 않는다.
- 로그인된 세션에서는 이 규약을 검증하지 않았다. 검증했다고 쓰지 않는다.
- 토큰 수를 추정해서 재시작 기준이나 예산에 쓰지 않는다.
