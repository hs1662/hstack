# 실제로 돌려 보는 읽기 노드 하나

빈 git 저장소에서 그대로 따라 할 수 있는 최소 왕복이다. Agy와 Claude Code 모두 명령은 같다. 바뀌는 건 플러그인 경로 변수와 2단계에서 호스트가 부르는 디스패치 도구뿐이다. 이 문서의 블록은 회귀 테스트가 직접 꺼내 실행하므로 바꿀 때는 엔진과 함께 맞춘다.

## 준비 파일

작업자가 읽을 대상이다.

```text notes.txt
graph v1 demo
second line
```

명세에는 노드 하나와 호스트가 미리 고른 게이트 명령을 넣는다. `gateArgv`는 컴파일 때 고정되고, 작업자 영수증으로는 바꿀 수 없다.

```json spec.json
{
  "schemaVersion": 1,
  "nodes": [
    {
      "id": "survey",
      "kind": "read",
      "prompt": "notes.txt를 읽고 무엇을 담은 파일인지 행 근거와 함께 보고한다.",
      "readScope": ["notes.txt"],
      "estimatedMinutes": 5,
      "gateArgv": ["test", "-s", "notes.txt"]
    }
  ]
}
```

작업자가 돌려줄 영수증이다. `factDigest`는 `scripts/graph/reducer.mjs`의 `factDigest(provenance)`가 네 배열(`evidenceSpans`, `claims`, `edgeCases`, `failureEvidence`)로 계산한 값이어야 한다. 손으로 고치면 `ERR_FORGED_EVIDENCE`로 거절된다. 행 번호는 1부터 세고 양 끝을 포함한다.

```json receipt.json
{
  "schemaVersion": 1,
  "workerReportedStatus": "completed",
  "inlineSummary": "notes.txt는 두 줄짜리 상태 메모다.",
  "provenance": {
    "evidenceSpans": [{ "spanId": "s1", "path": "notes.txt", "startLine": 1, "endLine": 2 }],
    "claims": [{ "claimId": "c1", "spanIds": ["s1"], "text": "notes.txt는 두 줄짜리 상태 메모다." }],
    "edgeCases": [],
    "failureEvidence": [],
    "factDigest": "82554b8a05db6d3c8478a31f1860221f1d5c4988126f9eaee2485747df465505"
  }
}
```

## 실행

`HOST_HANDLE`에는 실제로 띄운 작업자의 핸들을 넣는다. 아래 기본값은 혼자 돌려 보는 리허설용이다.

```sh run.sh
set -eu
graph() { node "${CLAUDE_PLUGIN_ROOT:-$PLUGIN_ROOT}/scripts/graph/cli.mjs" "$@"; }
field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).result[process.argv[1]])))' "$1"; }

graph host-caps
graph init
graph compile --run demo --spec spec.json --op-id compile-demo
graph ready --run demo
claim=$(graph claim --run demo --node survey --expected-rev 1 --op-id claim-survey)
echo "$claim"
token=$(printf '%s' "$claim" | field instructionPath)
graph start --token "$token" --host-handle "${HOST_HANDLE:-rehearsal-1}" --op-id start-survey
graph settle --token "$token" --outcome accepted --receipt receipt.json --op-id settle-survey
graph status --run demo
```

각 줄은 JSON 한 줄을 낸다. 이렇게 읽으면 된다.

| 명령 | 확인할 값 |
|---|---|
| `host-caps` | `dispatchHint`가 Agy면 `invoke_subagent`, Claude Code면 `Agent`다. `hintOnly: true`라서 세션 권한을 보장하지 않는다. |
| `compile` | `recommendation`이 `single_session`이다. 노드가 하나뿐이니 팬아웃할 이유가 없다. |
| `claim` | `result.instructionPath`가 토큰이다. 런, 시도, 루트에 묶여 있어 `start`와 `settle`에 `--run`이 필요 없다. 호스트만 갖고 있고 작업자에게는 넘기지 않는다. |
| `settle` | 엔진이 `gateArgv`를 직접 실행하고 그 측정을 CAS에 남긴다. 같은 `opId`로 다시 보내면 측정 없이 기록된 응답을 돌려준다. |
| `status` | `status`가 `completed`, `nodes.survey.status`가 `accepted`다. |

## 두 호스트에서

- **Agy:** `PLUGIN_ROOT`가 잡힌 상태에서 위 스크립트를 실행한다. `claim`과 `start` 사이에 `invoke_subagent`로 작업자를 부르고, 프롬프트에는 명세의 `prompt`와 `notes.txt`만 준다.
- **Claude Code:** `CLAUDE_PLUGIN_ROOT`가 먼저 쓰인다. 같은 자리에서 `Agent` 도구로 작업자를 부른다.
- **단일 세션 폴백:** 디스패치 도구가 없거나 거절되면, `compile`이 `single_session`을 권고했다면 같은 세션이 직접 읽고 영수증을 쓴다. 이때 `--host-handle`에는 세션 자신을 가리키는 값을 넣고, 작업자를 띄웠다고 기록하지 않는다. 엔진은 읽기 슬롯을 하나만 열어 주므로 순서대로 처리된다.

`ready`가 빈 페이지를 내도 끝난 게 아니다. `status`의 런 상태를 봐야 한다.
